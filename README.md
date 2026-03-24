# PasswordlessAuth

Minimalna demonstracija passwordless autentikacije sa sledecim funkcijama:

- Magic link login sa kriptografski jakim, vremenski ogranicenim i single-use tokenom
- TOTP (Google Authenticator kompatibilan) sa QR kodom
- Rate limiting i lockout nakon vise neuspelih pokusaja
- Recovery preko sekundarnog email-a, recovery tokena i recovery kodova
- Trusted device mehanizam
- Audit i auth logovi

## Pokretanje

1. Instaliraj zavisnosti:

```bash
npm install
```

2. Kopiraj `.env.example` u `.env` po potrebi.

3. Pokreni aplikaciju:

```bash
npm run dev
```

ili

```bash
npm start
```

4. Otvori `http://localhost:3000`

## Tok demonstracije

1. Unesi email i zatrazi magic link.
2. Otvori SMTP preview link koji aplikacija prikaze u UI-ju.
3. Klikni magic link.
4. Nakon prijave postavi sekundarni email i aktiviraj TOTP.
5. Sacuvaj recovery kodove.
6. Sledeci magic link login ce traziti i TOTP, osim ako oznacis uredjaj kao trusted.

## Fajlovi

- `server.js` - bootstrap Express servera
- `src/authRoutes.js` - auth, TOTP i recovery tokovi
- `src/db.js` - SQLite schema
- `logs/auth.log` - fajl log za auth i audit dogadjaje
- `db/app.db` - SQLite baza