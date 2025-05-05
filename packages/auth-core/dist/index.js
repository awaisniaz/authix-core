"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
class AuthService {
    constructor(jwtSecret, options = {
        accessTokenExpiresIn: '15m', // e.g., '15m'
        refreshTokenExpiresIn: '7d'
    }) {
        this.jwtSecret = jwtSecret;
        this.accessTokenExpiresIn = options.accessTokenExpiresIn ?? '15m';
        this.refreshTokenExpiresIn = options.refreshTokenExpiresIn ?? '7d';
        if (!jwtSecret) {
            throw new Error('JWT secret must be provided');
        }
    }
    async hashPassword(password) {
        return bcrypt_1.default.hash(password, 10);
    }
    async verifyPassword(password, hash) {
        return bcrypt_1.default.compare(password, hash);
    }
    generateAccessToken(userId) {
        return jsonwebtoken_1.default.sign({ userId }, this.jwtSecret, {
            expiresIn: '15m',
        });
    }
    generateRefreshToken(userId) {
        return jsonwebtoken_1.default.sign({ userId, type: 'refresh' }, this.jwtSecret, {
            expiresIn: '7h',
        });
    }
    verifyToken(token) {
        return jsonwebtoken_1.default.verify(token, this.jwtSecret);
    }
}
exports.AuthService = AuthService;
