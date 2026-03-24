const fs = require('fs');
const path = require('path');

const { config } = require('./config');

function appendLine(line) {
  fs.mkdirSync(path.dirname(config.authLogFile), { recursive: true });
  fs.appendFileSync(config.authLogFile, `${line}\n`, 'utf8');
}

async function logAttempt(db, { email, attemptType, success, ip, userAgent, details }) {
  const serializedDetails = details ? JSON.stringify(details) : null;
  appendLine(
    JSON.stringify({
      at: new Date().toISOString(),
      scope: 'attempt',
      email,
      attemptType,
      success,
      ip,
      userAgent,
      details,
    }),
  );

  await db.run(
    `
      INSERT INTO login_attempts (email, attempt_type, success, ip, user_agent, details)
      VALUES (?, ?, ?, ?, ?, ?)
    `,
    [email || null, attemptType, success ? 1 : 0, ip || null, userAgent || null, serializedDetails],
  );
}

async function auditLog(db, { userId, eventType, ip, userAgent, details }) {
  const serializedDetails = details ? JSON.stringify(details) : null;
  appendLine(
    JSON.stringify({
      at: new Date().toISOString(),
      scope: 'audit',
      userId,
      eventType,
      ip,
      userAgent,
      details,
    }),
  );

  await db.run(
    `
      INSERT INTO audit_logs (user_id, event_type, details, ip, user_agent)
      VALUES (?, ?, ?, ?, ?)
    `,
    [userId || null, eventType, serializedDetails, ip || null, userAgent || null],
  );
}

module.exports = { auditLog, logAttempt };