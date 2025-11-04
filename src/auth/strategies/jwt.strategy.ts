import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import axios from 'axios';
import * as jwksClient from 'jwks-rsa';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private jwksUri = 'http://localhost:8080/realms/soteria/protocol/openid-connect/certs';
  private client: jwksClient.JwksClient;

  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      algorithms: ['RS256'],
      secretOrKeyProvider: async (request, rawJwtToken, done) => {
        try {
          const decoded: any = JSON.parse(Buffer.from(rawJwtToken.split('.')[0], 'base64').toString());
          const kid = decoded.kid;
          const key = await this.getKey(kid);
          done(null, key);
        } catch (err) {
          done(err, null);
        }
      },
    });
    this.client = jwksClient({ jwksUri: this.jwksUri });
  }

  async getKey(kid: string): Promise<string> {
    return new Promise((resolve, reject) => {
      this.client.getSigningKey(kid, (err, key) => {
        if (err) reject(err);
        resolve(key.getPublicKey());
      });
    });
  }

  async validate(payload: any) {
    return payload; // attach user payload to request.user
  }
}
