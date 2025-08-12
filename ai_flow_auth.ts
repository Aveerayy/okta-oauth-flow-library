/**
 * Okta OAuth Flow Library
 * Provides reusable OAuth authentication, token management, and session handling
 */

import fetch from 'node-fetch';

// Types and Interfaces
export interface OktaConfig {
  clientId: string;
  clientSecret: string;
  issuer: string;
  redirectUri: string;
  scopes?: string[];
}

export interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  tokenType: string;
  scope?: string;
}

export interface UserSession {
  user: {
    id: string;
    email: string;
    name: string;
    groups?: string[];
  };
  tokens: TokenResponse;
  isAuthenticated: boolean;
}

export interface PKCECodePair {
  codeVerifier: string;
  codeChallenge: string;
}

// PKCE Helper Functions
export class PKCEHelper {
  static generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return this.base64URLEncode(array);
  }

  static async generateCodeChallenge(verifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return this.base64URLEncode(new Uint8Array(digest));
  }

  private static base64URLEncode(array: Uint8Array): string {
    return btoa(String.fromCharCode.apply(null, Array.from(array)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  static async generatePKCEPair(): Promise<PKCECodePair> {
    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = await this.generateCodeChallenge(codeVerifier);
    return { codeVerifier, codeChallenge };
  }
}

// Main Okta OAuth Client
export class OktaOAuthClient {
  private config: OktaConfig;
  private sessions: Map<string, UserSession> = new Map();

  constructor(config: OktaConfig) {
    this.config = {
      ...config,
      scopes: config.scopes || ['openid', 'profile', 'email']
    };
  }

  /**
   * Generate authorization URL for OAuth flow
   */
  async generateAuthUrl(state?: string, pkce?: PKCECodePair): Promise<{ url: string; pkce: PKCECodePair }> {
    const generatedPKCE = pkce || await PKCEHelper.generatePKCEPair();
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      response_type: 'code',
      scope: this.config.scopes!.join(' '),
      redirect_uri: this.config.redirectUri,
      code_challenge: generatedPKCE.codeChallenge,
      code_challenge_method: 'S256',
      ...(state && { state })
    });

    const authUrl = `${this.config.issuer}/v1/authorize?${params.toString()}`;
    return { url: authUrl, pkce: generatedPKCE };
  }

  /**
   * Exchange authorization code for tokens
   */
  async exchangeCodeForTokens(code: string, codeVerifier: string): Promise<TokenResponse> {
    const tokenUrl = `${this.config.issuer}/v1/token`;
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: codeVerifier
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: params.toString()
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token exchange failed: ${response.status} - ${errorText}`);
    }

    const data = await response.json() as any;
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: Date.now() + (data.expires_in * 1000),
      tokenType: data.token_type,
      scope: data.scope
    };
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
    const tokenUrl = `${this.config.issuer}/v1/token`;
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: params.toString()
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token refresh failed: ${response.status} - ${errorText}`);
    }

    const data = await response.json() as any;
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || refreshToken, // Some providers don't return new refresh token
      expiresAt: Date.now() + (data.expires_in * 1000),
      tokenType: data.token_type,
      scope: data.scope
    };
  }

  /**
   * Get user info using access token
   */
  async getUserInfo(accessToken: string): Promise<any> {
    const userInfoUrl = `${this.config.issuer}/v1/userinfo`;

    const response = await fetch(userInfoUrl, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to get user info: ${response.status} - ${errorText}`);
    }

    return response.json();
  }

  /**
   * Validate and refresh token if needed
   */
  async ensureValidToken(sessionId: string): Promise<string | null> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return null;
    }

    // Check if token is expired (with 5 minute buffer)
    const bufferTime = 5 * 60 * 1000; // 5 minutes
    if (Date.now() + bufferTime >= session.tokens.expiresAt) {
      try {
        const refreshedTokens = await this.refreshAccessToken(session.tokens.refreshToken);
        session.tokens = refreshedTokens;
        this.sessions.set(sessionId, session);
        return refreshedTokens.accessToken;
      } catch (error) {
        // Refresh failed, remove session
        this.sessions.delete(sessionId);
        return null;
      }
    }

    return session.tokens.accessToken;
  }

  /**
   * Create a new user session
   */
  async createSession(tokens: TokenResponse): Promise<string> {
    const userInfo = await this.getUserInfo(tokens.accessToken);
    const sessionId = this.generateSessionId();

    const session: UserSession = {
      user: {
        id: userInfo.sub,
        email: userInfo.email,
        name: userInfo.name,
        groups: userInfo.groups
      },
      tokens,
      isAuthenticated: true
    };

    this.sessions.set(sessionId, session);
    return sessionId;
  }

  /**
   * Get session by ID
   */
  getSession(sessionId: string): UserSession | null {
    return this.sessions.get(sessionId) || null;
  }

  /**
   * Remove session
   */
  removeSession(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  /**
   * Generate unique session ID
   */
  private generateSessionId(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Revoke tokens (logout)
   */
  async revokeTokens(accessToken: string, refreshToken?: string): Promise<void> {
    const revokeUrl = `${this.config.issuer}/v1/revoke`;

    // Revoke access token
    await this.revokeToken(revokeUrl, accessToken);

    // Revoke refresh token if provided
    if (refreshToken) {
      await this.revokeToken(revokeUrl, refreshToken);
    }
  }

  private async revokeToken(revokeUrl: string, token: string): Promise<void> {
    const params = new URLSearchParams({
      token,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret
    });

    const response = await fetch(revokeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString()
    });

    if (!response.ok) {
      console.warn(`Token revocation warning: ${response.status}`);
    }
  }
}

// Middleware Helper for Request Authentication
export interface AuthenticatedRequest {
  headers: { [key: string]: string };
  sessionId?: string;
  user?: UserSession['user'];
}

export class OktaMiddleware {
  private oktaClient: OktaOAuthClient;

  constructor(oktaClient: OktaOAuthClient) {
    this.oktaClient = oktaClient;
  }

  /**
   * Middleware function to ensure valid authentication
   */
  async withValidToken(sessionId: string): Promise<{
    isValid: boolean;
    headers?: { [key: string]: string };
    user?: UserSession['user'];
    error?: string
  }> {
    if (!sessionId) {
      return { isValid: false, error: 'No session ID provided' };
    }

    const session = this.oktaClient.getSession(sessionId);
    if (!session) {
      return { isValid: false, error: 'Invalid session' };
    }

    const validToken = await this.oktaClient.ensureValidToken(sessionId);
    if (!validToken) {
      return { isValid: false, error: 'Token validation failed' };
    }

    return {
      isValid: true,
      headers: {
        'Authorization': `Bearer ${validToken}`,
        'Content-Type': 'application/json'
      },
      user: session.user
    };
  }

  /**
   * Proxy authenticated requests to backend
   */
  async proxyRequest(
    sessionId: string,
    targetUrl: string,
    options: RequestInit = {}
  ): Promise<Response> {
    const auth = await this.withValidToken(sessionId);

    if (!auth.isValid) {
      throw new Error(auth.error || 'Authentication failed');
    }

    const headers = {
      ...auth.headers,
      ...options.headers
    };

    return fetch(targetUrl, {
      ...options,
      headers
    });
  }
}

// Utility function to initialize the library
export function createOktaClient(config: OktaConfig): {
  client: OktaOAuthClient;
  middleware: OktaMiddleware;
} {
  const client = new OktaOAuthClient(config);
  const middleware = new OktaMiddleware(client);

  return { client, middleware };
}

// Example usage and configuration helper
export const OktaConfigHelper = {
  fromEnv(): OktaConfig {
    const requiredEnvVars = {
      clientId: process.env.OKTA_CLIENT_ID,
      clientSecret: process.env.OKTA_CLIENT_SECRET,
      issuer: process.env.OKTA_ISSUER,
      redirectUri: process.env.OKTA_REDIRECT_URI
    };

    for (const [key, value] of Object.entries(requiredEnvVars)) {
      if (!value) {
        throw new Error(`Missing required environment variable: OKTA_${key.toUpperCase()}`);
      }
    }

    return requiredEnvVars as OktaConfig;
  }
};

// Export default instance factory
export default createOktaClient;
