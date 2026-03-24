const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const QRCode = require('qrcode');
const speakeasy = require('speakeasy');

const { config } = require('./config');
const { sendEmail } = require('./mailer');
const { auditLog, logAttempt } = require('./logger');
const {
  generateRecoveryCodes,
  generateToken,
  hashToken,
  normalizeEmail,
  normalizeRecoveryCode,
} = require('./security');

function buildAuthRouter(db) {
  const router = express.Router();

  const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Previse pokusaja. Pokusajte ponovo kasnije.',
  });

  const totpRateLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'TOTP rate limit je aktivan. Pokusajte uskoro ponovo.',
  });

  const recoveryRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 8,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Recovery rate limit je aktivan. Pokusajte kasnije.',
  });

  router.get('/', async (req, res) => {
    const user = req.session.userId ? await getUserById(db, req.session.userId) : null;
    const preAuthUser = req.session.preAuthUserId ? await getUserById(db, req.session.preAuthUserId) : null;
    const trustedDevices = user ? await listTrustedDevices(db, user.id) : [];
    const flash = consumeFlash(req);
    const recoveryCodes = req.session.recoveryCodes || [];
    const emailPreview = req.session.emailPreview || null;
    const recoveryPreview = req.session.recoveryPreview || null;

    req.session.recoveryCodes = [];
    req.session.emailPreview = null;
    req.session.recoveryPreview = null;

    let totpQrDataUrl = null;
    if (user && user.totp_secret && !user.totp_enabled) {
      const otpAuthUrl = speakeasy.otpauthURL({
        secret: user.totp_secret,
        label: `${config.appName}:${user.email}`,
        issuer: config.appName,
        encoding: 'base32',
      });
      totpQrDataUrl = await QRCode.toDataURL(otpAuthUrl);
    }

    res.render('index', {
      flash,
      user,
      preAuthUser,
      totpQrDataUrl,
      recoveryCodes,
      emailPreview,
      recoveryPreview,
      trustedDevices,
      config,
    });
  });

  router.get('/debug/db', async (_req, res, next) => {
    try {
      const [users, magicLinks, auditLogs, loginAttempts, recoveryTokens, recoveryCodes, trustedDevices] =
        await Promise.all([
          db.all(`SELECT id, email, secondary_email, totp_enabled, failed_auth_attempts, locked_until, created_at FROM users ORDER BY id DESC`),
          db.all(`SELECT id, user_id, expires_at, used_at, requested_ip, created_at FROM magic_links ORDER BY id DESC LIMIT 20`),
          db.all(`SELECT id, user_id, event_type, details, created_at FROM audit_logs ORDER BY id DESC LIMIT 20`),
          db.all(`SELECT id, email, attempt_type, success, details, created_at FROM login_attempts ORDER BY id DESC LIMIT 20`),
          db.all(`SELECT id, user_id, expires_at, used_at, created_at FROM recovery_tokens ORDER BY id DESC LIMIT 20`),
          db.all(`SELECT id, user_id, used_at, created_at FROM recovery_codes ORDER BY id DESC LIMIT 20`),
          db.all(`SELECT id, user_id, label, last_used_at, expires_at, created_at FROM trusted_devices ORDER BY id DESC LIMIT 20`),
        ]);

      res.render('debug-db', {
        users,
        magicLinks,
        auditLogs,
        loginAttempts,
        recoveryTokens,
        recoveryCodes,
        trustedDevices,
      });
    } catch (error) {
      return next(error);
    }
  });

  router.post('/auth/request-login', loginRateLimiter, async (req, res, next) => {
    try {
      const email = normalizeEmail(req.body.email);
      if (!isValidEmail(email)) {
        setFlash(req, 'error', 'Unesite ispravan email.');
        return res.redirect('/');
      }

      const user = await ensureUser(db, email);
      const rawToken = generateToken(32);
      const expiresAt = addMinutes(config.magicLinkTtlMinutes);
      const userAgent = req.get('user-agent') || null;
      const ip = getIp(req);

      await db.run(
        `
          INSERT INTO magic_links (user_id, token_hash, expires_at, requested_ip, requested_user_agent)
          VALUES (?, ?, ?, ?, ?)
        `,
        [user.id, hashToken(rawToken), expiresAt, ip, userAgent],
      );

      const loginUrl = `${config.baseUrl}/auth/verify-login?token=${encodeURIComponent(rawToken)}`;
      const emailResult = await sendEmail({
        to: email,
        subject: 'Vas magic link za prijavu',
        text: `Kliknite na link za prijavu: ${loginUrl}`,
        html: `<p>Kliknite na link za prijavu:</p><p><a href="${loginUrl}">${loginUrl}</a></p><p>Link vazi ${config.magicLinkTtlMinutes} minuta i moze se iskoristiti samo jednom.</p>`,
      });

      req.session.emailPreview = emailResult.previewUrl || emailResult.raw;
      setFlash(req, 'success', 'Magic link je generisan i poslat.', {
        hint: emailResult.previewUrl ? 'Za test SMTP otvorite preview link ispod.' : 'Email je zabelezen u lokalnom preview formatu.',
      });

      await logAttempt(db, {
        email,
        attemptType: 'magic-link-request',
        success: true,
        ip,
        userAgent,
        details: { expiresAt },
      });

      await auditLog(db, {
        userId: user.id,
        eventType: 'magic_link_requested',
        ip,
        userAgent,
        details: { expiresAt },
      });

      return res.redirect('/');
    } catch (error) {
      return next(error);
    }
  });

  router.get('/auth/verify-login', async (req, res, next) => {
    try {
      const token = String(req.query.token || '');
      const userAgent = req.get('user-agent') || null;
      const ip = getIp(req);
      if (!token) {
        setFlash(req, 'error', 'Token nedostaje.');
        return res.redirect('/');
      }

      const record = await db.get(
        `
          SELECT ml.id, ml.user_id, u.email, u.totp_enabled, u.locked_until
          FROM magic_links ml
          JOIN users u ON u.id = ml.user_id
          WHERE ml.token_hash = ?
            AND ml.used_at IS NULL
            AND datetime(ml.expires_at) > datetime('now')
        `,
        [hashToken(token)],
      );

      if (!record) {
        await logAttempt(db, {
          email: null,
          attemptType: 'magic-link-verify',
          success: false,
          ip,
          userAgent,
          details: { reason: 'invalid-or-expired' },
        });
        setFlash(req, 'error', 'Magic link nije validan ili je istekao.');
        return res.redirect('/');
      }

      if (isLocked(record)) {
        setFlash(req, 'error', 'Nalog je privremeno zakljucan zbog neuspelih pokusaja.');
        return res.redirect('/');
      }

      await db.run(`UPDATE magic_links SET used_at = CURRENT_TIMESTAMP WHERE id = ?`, [record.id]);

      await logAttempt(db, {
        email: record.email,
        attemptType: 'magic-link-verify',
        success: true,
        ip,
        userAgent,
        details: { singleUse: true },
      });

      const trusted = await hasTrustedDevice(db, req, record.user_id);
      if (record.totp_enabled && !trusted) {
        req.session.preAuthUserId = record.user_id;
        delete req.session.userId;

        await auditLog(db, {
          userId: record.user_id,
          eventType: 'magic_link_verified_pending_totp',
          ip,
          userAgent,
          details: { trustedDevice: false },
        });

        setFlash(req, 'success', 'Magic link je validan. Unesite TOTP kod za zavrsetak prijave.');
        return res.redirect('/');
      }

      await completeLogin(req, record.user_id);
      await auditLog(db, {
        userId: record.user_id,
        eventType: 'login_success_magic_link',
        ip,
        userAgent,
        details: { trustedDevice: trusted },
      });
      setFlash(req, 'success', 'Prijava je uspesna.');
      return res.redirect('/');
    } catch (error) {
      return next(error);
    }
  });

  router.post('/auth/setup-totp', requireLogin, async (req, res, next) => {
    try {
      const user = await getUserById(db, req.session.userId);
      const secret = speakeasy.generateSecret({
        name: `${config.appName}:${user.email}`,
        issuer: config.appName,
        length: 32,
      });

      await db.run(
        `
          UPDATE users
          SET totp_secret = ?, totp_enabled = 0, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `,
        [secret.base32, user.id],
      );

      await auditLog(db, {
        userId: user.id,
        eventType: 'totp_secret_generated',
        ip: getIp(req),
        userAgent: req.get('user-agent') || null,
        details: {},
      });

      setFlash(req, 'success', 'TOTP secret je generisan. Skenirajte QR kod i unesite kod za aktivaciju.');
      return res.redirect('/');
    } catch (error) {
      return next(error);
    }
  });

  router.post('/auth/enable-totp', requireLogin, async (req, res, next) => {
    try {
      const user = await getUserById(db, req.session.userId);
      const token = String(req.body.token || '').trim();
      if (!user?.totp_secret) {
        setFlash(req, 'error', 'Prvo generisite TOTP secret.');
        return res.redirect('/');
      }

      const valid = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token,
        window: 1,
      });

      if (!valid) {
        setFlash(req, 'error', 'TOTP kod nije ispravan.');
        return res.redirect('/');
      }

      await db.run(
        `
          UPDATE users
          SET totp_enabled = 1, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `,
        [user.id],
      );

      const recoveryCodes = await regenerateRecoveryCodes(db, user.id);
      req.session.recoveryCodes = recoveryCodes;

      await auditLog(db, {
        userId: user.id,
        eventType: 'totp_enabled',
        ip: getIp(req),
        userAgent: req.get('user-agent') || null,
        details: { recoveryCodesGenerated: recoveryCodes.length },
      });

      setFlash(req, 'success', 'TOTP je aktiviran. Sacuvajte recovery kodove.');
      return res.redirect('/');
    } catch (error) {
      return next(error);
    }
  });

  router.post('/auth/verify-totp', totpRateLimiter, async (req, res, next) => {
    try {
      const userAgent = req.get('user-agent') || null;
      const ip = getIp(req);
      const token = String(req.body.token || '').trim();

      if (!req.session.preAuthUserId) {
        setFlash(req, 'error', 'Nema aktivnog pre-auth koraka za TOTP.');
        return res.redirect('/');
      }

      const user = await getUserById(db, req.session.preAuthUserId);
      if (!user || !user.totp_enabled || !user.totp_secret) {
        setFlash(req, 'error', 'TOTP nije dostupan za ovaj nalog.');
        return res.redirect('/');
      }

      if (isLocked(user)) {
        setFlash(req, 'error', 'Nalog je privremeno zakljucan.');
        return res.redirect('/');
      }

      const valid = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token,
        window: 1,
      });

      if (!valid) {
        await registerFailedAuth(db, user.id);
        await logAttempt(db, {
          email: user.email,
          attemptType: 'totp-verify',
          success: false,
          ip,
          userAgent,
          details: { reason: 'invalid-code' },
        });

        setFlash(req, 'error', 'TOTP kod nije ispravan.');
        return res.redirect('/');
      }

      await resetFailedAuth(db, user.id);
      await completeLogin(req, user.id);

      await logAttempt(db, {
        email: user.email,
        attemptType: 'totp-verify',
        success: true,
        ip,
        userAgent,
        details: { trustDevice: false },
      });

      await auditLog(db, {
        userId: user.id,
        eventType: 'login_success_totp',
        ip,
        userAgent,
        details: { trustDevice: false },
      });

      setFlash(req, 'success', 'TOTP provera je uspesna.');
      return res.redirect('/');
    } catch (error) {
      return next(error);
    }
  });

  router.post('/auth/secondary-email', requireLogin, async (req, res, next) => {
    try {
      const secondaryEmail = normalizeEmail(req.body.secondaryEmail);
      if (!isValidEmail(secondaryEmail)) {
        setFlash(req, 'error', 'Unesite ispravan sekundarni email.');
        return res.redirect('/');
      }

      await db.run(
        `
          UPDATE users
          SET secondary_email = ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `,
        [secondaryEmail, req.session.userId],
      );

      await auditLog(db, {
        userId: req.session.userId,
        eventType: 'secondary_email_updated',
        ip: getIp(req),
        userAgent: req.get('user-agent') || null,
        details: { secondaryEmail },
      });

      setFlash(req, 'success', 'Sekundarni email je sacuvan.');
      return res.redirect('/');
    } catch (error) {
      return next(error);
    }
  });

  router.post('/auth/recovery-request', recoveryRateLimiter, async (req, res, next) => {
    try {
      const email = normalizeEmail(req.body.email);
      const userAgent = req.get('user-agent') || null;
      const ip = getIp(req);

      if (isValidEmail(email)) {
        const user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);
        if (user?.secondary_email) {
          const rawToken = generateToken(32);
          const expiresAt = addHours(config.recoveryTokenTtlHours);

          await db.run(
            `
              INSERT INTO recovery_tokens (user_id, token_hash, expires_at)
              VALUES (?, ?, ?)
            `,
            [user.id, hashToken(rawToken), expiresAt],
          );

          const recoveryUrl = `${config.baseUrl}/auth/recovery-verify?token=${encodeURIComponent(rawToken)}`;
          const emailResult = await sendEmail({
            to: user.secondary_email,
            subject: 'Recovery link za pristup nalogu',
            text: `Kliknite na recovery link: ${recoveryUrl}`,
            html: `<p>Recovery link za nalog ${user.email}:</p><p><a href="${recoveryUrl}">${recoveryUrl}</a></p><p>Link vazi ${config.recoveryTokenTtlHours} sata.</p>`,
          });

          req.session.recoveryPreview = emailResult.previewUrl || emailResult.raw;

          await auditLog(db, {
            userId: user.id,
            eventType: 'recovery_requested',
            ip,
            userAgent,
            details: { secondaryEmail: user.secondary_email, expiresAt },
          });
        }
      }

      await logAttempt(db, {
        email,
        attemptType: 'recovery-request',
        success: true,
        ip,
        userAgent,
        details: { genericResponse: true },
      });

      setFlash(req, 'success', 'Ako nalog postoji i ima recovery opciju, recovery email je poslat.');
      return res.redirect('/');
    } catch (error) {
      return next(error);
    }
  });

  router.get('/auth/recovery-verify', async (req, res, next) => {
    try {
      const token = String(req.query.token || '');
      const userAgent = req.get('user-agent') || null;
      const ip = getIp(req);
      if (!token) {
        setFlash(req, 'error', 'Recovery token nedostaje.');
        return res.redirect('/');
      }

      const record = await db.get(
        `
          SELECT rt.id, rt.user_id, u.email
          FROM recovery_tokens rt
          JOIN users u ON u.id = rt.user_id
          WHERE rt.token_hash = ?
            AND rt.used_at IS NULL
            AND datetime(rt.expires_at) > datetime('now')
        `,
        [hashToken(token)],
      );

      if (!record) {
        await logAttempt(db, {
          email: null,
          attemptType: 'recovery-verify',
          success: false,
          ip,
          userAgent,
          details: { reason: 'invalid-or-expired' },
        });
        setFlash(req, 'error', 'Recovery token nije validan ili je istekao.');
        return res.redirect('/');
      }

      await db.run(`UPDATE recovery_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?`, [record.id]);
      await completeLogin(req, record.user_id);

      await logAttempt(db, {
        email: record.email,
        attemptType: 'recovery-verify',
        success: true,
        ip,
        userAgent,
        details: { singleUse: true },
      });

      await auditLog(db, {
        userId: record.user_id,
        eventType: 'recovery_login_success',
        ip,
        userAgent,
        details: {},
      });

      setFlash(req, 'success', 'Recovery prijava je uspesna.');
      return res.redirect('/');
    } catch (error) {
      return next(error);
    }
  });

  router.post('/auth/recovery-code-login', recoveryRateLimiter, async (req, res, next) => {
    try {
      const email = normalizeEmail(req.body.email);
      const code = normalizeRecoveryCode(req.body.code);
      const userAgent = req.get('user-agent') || null;
      const ip = getIp(req);
      const user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);

      if (!user) {
        setFlash(req, 'error', 'Recovery kod nije validan.');
        return res.redirect('/');
      }

      if (isLocked(user)) {
        setFlash(req, 'error', 'Nalog je privremeno zakljucan.');
        return res.redirect('/');
      }

      const record = await db.get(
        `
          SELECT id
          FROM recovery_codes
          WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
        `,
        [user.id, hashToken(code)],
      );

      if (!record) {
        await registerFailedAuth(db, user.id);
        await logAttempt(db, {
          email,
          attemptType: 'recovery-code-login',
          success: false,
          ip,
          userAgent,
          details: { reason: 'invalid-code' },
        });
        setFlash(req, 'error', 'Recovery kod nije validan.');
        return res.redirect('/');
      }

      await db.run(`UPDATE recovery_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ?`, [record.id]);
      await resetFailedAuth(db, user.id);
      await completeLogin(req, user.id);

      await logAttempt(db, {
        email,
        attemptType: 'recovery-code-login',
        success: true,
        ip,
        userAgent,
        details: { singleUse: true },
      });

      await auditLog(db, {
        userId: user.id,
        eventType: 'recovery_code_login_success',
        ip,
        userAgent,
        details: {},
      });

      setFlash(req, 'success', 'Recovery kod je prihvacen.');
      return res.redirect('/');
    } catch (error) {
      return next(error);
    }
  });

  router.post('/auth/recovery-codes/regenerate', requireLogin, async (req, res, next) => {
    try {
      const user = await getUserById(db, req.session.userId);
      if (!user?.totp_enabled) {
        setFlash(req, 'error', 'Prvo aktivirajte TOTP da biste koristili recovery kodove.');
        return res.redirect('/');
      }

      const recoveryCodes = await regenerateRecoveryCodes(db, req.session.userId);
      req.session.recoveryCodes = recoveryCodes;

      await auditLog(db, {
        userId: req.session.userId,
        eventType: 'recovery_codes_regenerated',
        ip: getIp(req),
        userAgent: req.get('user-agent') || null,
        details: { count: recoveryCodes.length },
      });

      setFlash(req, 'success', 'Generisani su novi recovery kodovi.');
      return res.redirect('/');
    } catch (error) {
      return next(error);
    }
  });

  router.post('/auth/logout', async (req, res) => {
    req.session.destroy(() => {
      res.redirect('/');
    });
  });

  return router;
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    setFlash(req, 'error', 'Morate biti prijavljeni.');
    return res.redirect('/');
  }

  return next();
}

async function ensureUser(db, email) {
  let user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);
  if (!user) {
    const result = await db.run(`INSERT INTO users (email) VALUES (?)`, [email]);
    user = await getUserById(db, result.lastID);
  }
  return user;
}

async function getUserById(db, id) {
  return db.get(`SELECT * FROM users WHERE id = ?`, [id]);
}

async function regenerateRecoveryCodes(db, userId) {
  const recoveryCodes = generateRecoveryCodes(8);
  await db.run(`DELETE FROM recovery_codes WHERE user_id = ?`, [userId]);
  for (const recoveryCode of recoveryCodes) {
    await db.run(
      `
        INSERT INTO recovery_codes (user_id, code_hash)
        VALUES (?, ?)
      `,
      [userId, hashToken(normalizeRecoveryCode(recoveryCode))],
    );
  }

  return recoveryCodes;
}

async function registerFailedAuth(db, userId) {
  const user = await getUserById(db, userId);
  const failures = Number(user.failed_auth_attempts || 0) + 1;
  const shouldLock = failures >= config.maxAuthFailures;
  const lockedUntil = shouldLock ? addMinutes(config.accountLockMinutes) : null;

  await db.run(
    `
      UPDATE users
      SET failed_auth_attempts = ?, locked_until = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `,
    [shouldLock ? 0 : failures, lockedUntil, userId],
  );
}

async function resetFailedAuth(db, userId) {
  await db.run(
    `
      UPDATE users
      SET failed_auth_attempts = 0, locked_until = NULL, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `,
    [userId],
  );
}

async function completeLogin(req, userId) {
  req.session.userId = userId;
  delete req.session.preAuthUserId;
}

async function hasTrustedDevice(db, req, userId) {
  const deviceToken = req.cookies?.[config.trustedDeviceCookie] || parseCookie(req, config.trustedDeviceCookie);
  if (!deviceToken) {
    return false;
  }

  const record = await db.get(
    `
      SELECT id
      FROM trusted_devices
      WHERE user_id = ? AND device_hash = ? AND datetime(expires_at) > datetime('now')
    `,
    [userId, hashToken(deviceToken)],
  );

  if (!record) {
    return false;
  }

  await db.run(`UPDATE trusted_devices SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, [record.id]);
  return true;
}

async function issueTrustedDevice(db, req, res, userId) {
  const deviceToken = generateToken(24);
  const label = buildDeviceLabel(req);
  await db.run(
    `
      INSERT INTO trusted_devices (user_id, device_hash, label, last_used_at, expires_at)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)
    `,
    [userId, hashToken(deviceToken), label, addDays(config.trustedDeviceDays)],
  );

  res.cookie(config.trustedDeviceCookie, deviceToken, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: config.trustedDeviceDays * 24 * 60 * 60 * 1000,
  });
}

async function listTrustedDevices(db, userId) {
  return db.all(
    `
      SELECT label, created_at, last_used_at, expires_at
      FROM trusted_devices
      WHERE user_id = ? AND datetime(expires_at) > datetime('now')
      ORDER BY created_at DESC
    `,
    [userId],
  );
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isLocked(user) {
  return Boolean(user?.locked_until && new Date(user.locked_until).getTime() > Date.now());
}

function setFlash(req, type, text, extra = {}) {
  req.session.flash = { type, text, ...extra };
}

function consumeFlash(req) {
  const flash = req.session.flash || null;
  delete req.session.flash;
  return flash;
}

function getIp(req) {
  return req.ip || req.connection?.remoteAddress || null;
}

function addMinutes(minutes) {
  return new Date(Date.now() + minutes * 60 * 1000).toISOString();
}

function addHours(hours) {
  return new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
}

function addDays(days) {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function buildDeviceLabel(req) {
  const userAgent = req.get('user-agent') || 'Unknown device';
  return userAgent.slice(0, 120);
}

function parseCookie(req, key) {
  const cookieHeader = req.headers.cookie || '';
  const parts = cookieHeader.split(';').map((part) => part.trim());
  for (const part of parts) {
    if (part.startsWith(`${key}=`)) {
      return decodeURIComponent(part.slice(key.length + 1));
    }
  }
  return null;
}

module.exports = { buildAuthRouter };