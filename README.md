# Passwordless Authentication App

Node.js/Express demonstracija passwordless autentikacije za potrebe projekta (diplomskog rada), sa fokusom na sigurnu prijavu bez lozinke i oporavak pristupa nalogu.

## Funkcionalnosti

- Magic link prijava sa vremenski ogranicenim i jednokratnim tokenom
- TOTP (Google Authenticator kompatibilan) sa QR aktivacijom
- Rate limiting i privremeni lockout nakon vise neuspelih pokusaja
- Recovery tokovi: sekundarni email, recovery link i recovery kodovi
- Audit i login attempt logovanje dogadjaja

## Tehnologije

- Node.js
- Express
- SQLite
- EJS
- Nodemailer
- Speakeasy (TOTP)

## Pokretanje projekta

1. Instalirati zavisnosti:

```bash
npm install
```

2. Pripremiti konfiguraciju:

- Kopirati `.env.example` u `.env`
- Podesiti vrednosti promenljivih po potrebi

3. Pokrenuti aplikaciju:

```bash
npm start
```

Za development mod moze i:

```bash
npm run dev
```

4. Otvoriti aplikaciju na:

`http://localhost:3000`

## Brzi demo scenario

1. Uneti email i zatraziti magic link.
2. Otvoriti SMTP preview link prikazan u aplikaciji.
3. Potvrditi prijavu preko magic linka.
4. Aktivirati TOTP i sacuvati recovery kodove.
5. Testirati recovery prijavu (link ili recovery kod).

## Struktura projekta

- `server.js` - inicijalizacija Express servera
- `src/authRoutes.js` - autentikacioni i recovery tokovi
- `src/db.js` - inicijalizacija baze i schema
- `src/security.js` - token/hash pomocne funkcije
- `views/` - EJS prikazi