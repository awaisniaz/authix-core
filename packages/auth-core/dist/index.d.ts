export interface AuthUser {
    id: string;
    email: string;
    passwordHash: string;
}
interface TokenOptions {
    accessTokenExpiresIn: string;
    refreshTokenExpiresIn: string;
}
export declare class AuthService {
    private jwtSecret;
    private accessTokenExpiresIn;
    private refreshTokenExpiresIn;
    constructor(jwtSecret: string, options?: TokenOptions);
    hashPassword(password: string): Promise<string>;
    verifyPassword(password: string, hash: string): Promise<boolean>;
    generateAccessToken(userId: string): string;
    generateRefreshToken(userId: string): string;
    verifyToken(token: string): any;
}
export {};
