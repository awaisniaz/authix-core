import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export interface AuthUser {
  id: string;
  email: string;
  passwordHash: string;
}
interface TokenOptions {
    accessTokenExpiresIn: string;   // e.g., '15m'
    refreshTokenExpiresIn: string;  // e.g., '7d'
  }
  

export class AuthService {
    private accessTokenExpiresIn: string | number;
  private refreshTokenExpiresIn: string | number;
  constructor(
    private jwtSecret: string,
    options: TokenOptions = {
        accessTokenExpiresIn: '15m',   // e.g., '15m'
    refreshTokenExpiresIn: '7d'
    },
  ) {
    this.accessTokenExpiresIn = options.accessTokenExpiresIn ?? '15m';
    this.refreshTokenExpiresIn = options.refreshTokenExpiresIn ?? '7d';

    if (!jwtSecret) {
      throw new Error('JWT secret must be provided');
    }
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  generateAccessToken(userId: string): string {
    return jwt.sign({ userId }, this.jwtSecret, {
      expiresIn: '15m',
    });
  }

  generateRefreshToken(userId: string): string {
    return jwt.sign({ userId, type: 'refresh' }, this.jwtSecret, {
      expiresIn: '7h',
    });
  }

  verifyToken(token: string): any {
    return jwt.verify(token, this.jwtSecret);
  }
}
