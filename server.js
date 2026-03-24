const express = require('express');
const session = require('express-session');
const path = require('path');

const { config } = require('./src/config');
const { initDb } = require('./src/db');
const { buildAuthRouter } = require('./src/authRoutes');

async function startServer() {
  const db = await initDb();
  const app = express();

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(
    session({
      name: 'passwordless.sid',
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
        maxAge: 1000 * 60 * 60 * 8,
      },
    }),
  );

  app.use(buildAuthRouter(db));

  app.use((error, _req, res, _next) => {
    console.error(error);
    res.status(500).render('index', {
      flash: { type: 'error', text: 'Doslo je do greske na serveru.' },
      user: null,
      preAuthUser: null,
      totpQrDataUrl: null,
      recoveryCodes: [],
      emailPreview: null,
      recoveryPreview: null,
      trustedDevices: [],
      config,
    });
  });

  app.listen(config.port, () => {
    console.log(`PasswordlessAuth running on ${config.baseUrl}`);
  });
}

startServer().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});