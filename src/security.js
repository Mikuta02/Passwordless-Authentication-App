const crypto = require('crypto');

function generateToken(size = 32) {
  return crypto.randomBytes(size).toString('base64url');
}

function hashToken(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function normalizeRecoveryCode(code) {
  return String(code || '').replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
}

function generateRecoveryCodes(count = 8) {
  return Array.from({ length: count }, () => {
    const left = crypto.randomBytes(3).toString('hex').toUpperCase();
    const right = crypto.randomBytes(3).toString('hex').toUpperCase();
    return `${left}-${right}`;
  });
}

module.exports = {
  generateRecoveryCodes,
  generateToken,
  hashToken,
  normalizeEmail,
  normalizeRecoveryCode,
};