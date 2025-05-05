# 🔐 Authix - Authentication Made Simple

> A lightweight, extensible authentication library for Node.js and NestJS.

`authix` is a modular, production-ready authentication solution that provides everything you need to handle user auth — including password hashing, access/refresh tokens, and basic auth flows — in both raw Node.js and NestJS applications.

---

## 📦 Packages

| Package                       | Description                     |
|------------------------------|---------------------------------|
| [`@cryptarastudio/authix-core`](https://www.npmjs.com/package/@cryptarastudio/authix-core) | Node.js authentication logic 
---

## ✨ Features

- ✅ Password hashing with bcrypt
- 🔐 Access & Refresh Token generation (JWT-based)
- 🔁 Refresh token rotation support
- 🧱 Designed for reusability and extendability
- ⚙️ Use in **any Node.js project** or with **NestJS** out of the box

---

## 📀 Installation

### For Node.js Projects

```bash
npm install @cryptarastudio/authix-core


🔧 Features
Feature	Description
✅ hashPassword	Hashes password using bcrypt with salt
✅ verifyPassword	Verifies raw password against hashed one
✅ generateAccessToken	Creates a signed JWT token for short-term session
✅ generateRefreshToken	Issues long-lived refresh tokens
✅ verifyToken	Decodes and validates a JWT (access or refresh)
✅ Fully TypeScript Ready	All types & interfaces included
✅ Minimal footprint	Does only one job and does it well

📘 Function Reference
🧂 hashPassword(password: string): Promise<string>
Securely hash a user's password using bcrypt.

const hashed = await auth.hashPassword('admin123');

🔍 verifyPassword(plain: string, hashed: string): Promise<boolean>
Compare a raw password with a hashed one.

const isValid = await auth.verifyPassword('admin123', hashed);

🔐 generateAccessToken(userId: string): string
Generate a signed access token (JWT). Default expiration: 15m.

const token = auth.generateAccessToken('user123');

♻️ generateRefreshToken(userId: string): string
Generate a signed refresh token. Default expiration: 7d.

const refresh = auth.generateRefreshToken('user123');

🛡️ verifyToken(token: string): object | null
Verify and decode a JWT. Returns null if invalid or expired.

const payload = auth.verifyToken(accessToken);

💡 Full Example
import { AuthService } from '@cryptara/authix-core';

// Create instance with your JWT secret
const auth = new AuthService('secret123');

async function main() {
  // 1. Hash password before storing in DB
  const hashed = await auth.hashPassword('password');

  // 2. Validate password during login
  const valid = await auth.verifyPassword('password', hashed);

  // 3. Generate access & refresh tokens
  const access = auth.generateAccessToken('user123');
  const refresh = auth.generateRefreshToken('user123');

  // 4. Verify access token
  const decoded = auth.verifyToken(access);

  console.log({ hashed, valid, access, refresh, decoded });
}

main();


⚙️ Constructor
new AuthService(jwtSecret: string, accessTokenExpiry = '15m', refreshTokenExpiry = '7d')

Parameter	Type	Description
jwtSecret	string	Secret used for signing tokens
accessTokenExpiry	string	Optional, default '15m'
refreshTokenExpiry	string	Optional, default '7d'

🧩 Ideal For
RESTful APIs (NestJS / Express)

Microservices

SaaS Applications

Admin Panels

🛠 Maintainer
Made with ❤️ by Cryptara Studio
  
  

