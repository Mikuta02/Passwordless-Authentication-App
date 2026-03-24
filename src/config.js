const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const port = Number(process.env.PORT || 3000);

const config = {
  port,
  baseUrl: process.env.BASE_URL || `http://localhost:${port}`,
  sessionSecret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  dbFile: path.join(__dirname, '..', 'db', 'app.db'),
  authLogFile: path.join(__dirname, '..', 'logs', 'auth.log'),
  smtp: {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.SMTP_FROM || 'Passwordless Auth <no-reply@example.com>',
  },
  magicLinkTtlMinutes: 10,
  recoveryTokenTtlHours: 24,
  maxAuthFailures: 5,
  accountLockMinutes: 15,
  trustedDeviceDays: 30,
  trustedDeviceCookie: 'trusted_device',
  appName: 'PasswordlessAuth',
};

module.exports = { config };