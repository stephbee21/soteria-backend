// src/auth/auth.controller.ts
import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  Query,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /** OIDC Discovery */
  @Get('.well-known/openid-configuration')
  getConfig() {
    return {
      issuer: 'http://localhost:8080/realms/soteria',
      authorization_endpoint: '/oauth2/authorize',
      token_endpoint: '/oauth2/token',
      jwks_uri: '/jwks',
      userinfo_endpoint: '/userinfo',
    };
  }

  /** OAuth2 Authorize (for browser-based flows) */
  @Get('oauth2/authorize')
  authorize(@Query() query: any) {
    // Normally redirect to Keycloak login page
    return { message: 'Redirect to Keycloak authorize endpoint', query };
  }

  /** Token endpoint */
  @Post('oauth2/token')
  async token(@Body() body: any) {
    const { username, password, refresh_token, grant_type } = body;

    if (grant_type === 'password') {
      return this.authService.login(username, password);
    } else if (grant_type === 'refresh_token') {
      return this.authService.refreshToken(refresh_token);
    }

    throw new UnauthorizedException('Unsupported grant type');
  }

  /** JWKS endpoint */
  @Get('jwks')
  async getJwks() {
    return { keys: [] }; // you could proxy Keycloak’s JWKS instead
  }

  /** Userinfo endpoint */
  @Get('userinfo')
  async userinfo(@Req() req: any) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) throw new UnauthorizedException('Missing token');
    return this.authService.userinfo(token);
  }

  /** Registration */
  @Post('auth/register')
  async register(@Body() body: any) {
    // Extend this to call Keycloak Admin API
    return { message: 'User registered (stub)', body };
  }

  /** Login */
  @Post('auth/login')
  async login(@Body() body: any) {
    return this.authService.login(body.username, body.password);
  }

  /** Logout */
  @Post('auth/logout')
  async logout(@Body('refresh_token') refreshToken: string) {
    return this.authService.logout(refreshToken);
  }

  /** Refresh */
  @Post('auth/refresh')
  async refresh(@Body('refresh_token') refreshToken: string) {
    return this.authService.refreshToken(refreshToken);
  }

  /** Password reset */
  @Post('auth/password-reset')
  async passwordReset(@Body('email') email: string) {
    // Could call Keycloak’s "execute-actions-email"
    return { message: `Password reset link sent to ${email}` };
  }

  @Get('ping')
  ping() {
    return { message: 'pong' };
  }

  
}
