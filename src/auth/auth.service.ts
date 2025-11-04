// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import axios from 'axios';
import jwksClient from 'jwks-rsa';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
  private keycloakBase = 'http://localhost:8080/realms/soteria/protocol/openid-connect';
  private client: jwksClient.JwksClient;

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {
    this.client = jwksClient({ jwksUri: `${this.keycloakBase}/certs` });
  }

  /** 🔹 Validate token against JWKS */
  async validateToken(token: string) {
    const decoded: any = jwt.decode(token, { complete: true });
    if (!decoded) throw new UnauthorizedException('Invalid token');

    const key = await this.getKey(decoded.header.kid);
    try {
      return jwt.verify(token, key, { algorithms: ['RS256'] });
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private async getKey(kid: string): Promise<string> {
    return new Promise((resolve, reject) => {
      this.client.getSigningKey(kid, (err, key) => {
        if (err || !key) return reject(err ?? new Error('No signing key found'));
        resolve(key.getPublicKey());
      });
    });
  }

  /** 🔹 Proxy login to Keycloak */
  async login(username: string, password: string) {
    try {
      const res = await axios.post(
        `${this.keycloakBase}/token`,
        new URLSearchParams({
          client_id: 'soteria-client',
          grant_type: 'password',
          username,
          password,
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
      );

      return res.data; // contains access_token, refresh_token, id_token, expires_in, etc.
    } catch {
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  /** 🔹 Proxy refresh to Keycloak */
  async refreshToken(refreshToken: string) {
    const res = await axios.post(
      `${this.keycloakBase}/token`,
      new URLSearchParams({
        client_id: 'soteria-client',
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    );

    return res.data;
  }

  /** 🔹 Proxy logout */
  async logout(refreshToken: string) {
    await axios.post(
      `${this.keycloakBase}/logout`,
      new URLSearchParams({
        client_id: 'soteria-client',
        refresh_token: refreshToken,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    );
    return { message: 'Logged out successfully' };
  }

  /** 🔹 Userinfo endpoint */
  async userinfo(accessToken: string) {
    const res = await axios.get(`${this.keycloakBase}/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return res.data;
  }
}
