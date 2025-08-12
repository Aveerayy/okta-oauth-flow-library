/**
 * Example Usage of Okta OAuth Flow Library
 * Demonstrates how to use the library in different scenarios
 */

import { createOktaClient, OktaConfigHelper, PKCEHelper } from './ai_flow_auth';

// Example 1: Basic setup and initialization
async function initializeOktaClient() {
  // Option 1: From environment variables
  const config = OktaConfigHelper.fromEnv();

  // Option 2: Manual configuration
  // const config = {
  //   clientId: 'your-client-id',
  //   clientSecret: 'your-client-secret',
  //   issuer: 'https://dev-123456.okta.com/oauth2/default',
  //   redirectUri: 'http://localhost:3000/api/auth/callback',
  //   scopes: ['openid', 'profile', 'email', 'groups']
  // };

  const { client, middleware } = createOktaClient(config);
  return { client, middleware };
}

// Example 2: Complete OAuth Flow (for web applications)
async function webAppOAuthFlow() {
  const { client } = await initializeOktaClient();

  // Step 1: Generate authorization URL
  const { url: authUrl, pkce } = await client.generateAuthUrl('random-state-value');
  console.log('Redirect user to:', authUrl);

  // Store PKCE code verifier in session/memory for the callback
  // In a real app, you'd store this in session storage or database
  const sessionStorage = new Map();
  sessionStorage.set('pkce_verifier', pkce.codeVerifier);

  // Step 2: Handle callback (after user authorizes)
  // This would typically be in your callback route handler
  const handleCallback = async (authorizationCode: string) => {
    const codeVerifier = sessionStorage.get('pkce_verifier');

    try {
      // Exchange code for tokens
      const tokens = await client.exchangeCodeForTokens(authorizationCode, codeVerifier);

      // Create user session
      const sessionId = await client.createSession(tokens);

      console.log('User logged in successfully. Session ID:', sessionId);
      return sessionId;
    } catch (error) {
      console.error('OAuth callback error:', error);
      throw error;
    }
  };

  return { handleCallback };
}

// Example 3: API Request with automatic token refresh
async function makeAuthenticatedAPIRequest(sessionId: string) {
  const { middleware } = await initializeOktaClient();

  try {
    // Make authenticated request to your backend API
    const response = await middleware.proxyRequest(
      sessionId,
      'https://api.yourbackend.com/protected-endpoint',
      {
        method: 'GET'
      }
    );

    const data = await response.json();
    console.log('API Response:', data);
    return data;
  } catch (error) {
    console.error('API request failed:', error);
    throw error;
  }
}

// Example 4: Session management
async function sessionManagementExample() {
  const { client } = await initializeOktaClient();

  // Get session information
  const getSessionInfo = (sessionId: string) => {
    const session = client.getSession(sessionId);
    if (session) {
      console.log('User:', session.user);
      console.log('Authenticated:', session.isAuthenticated);
      console.log('Token expires at:', new Date(session.tokens.expiresAt));
    }
    return session;
  };

  // Logout user
  const logout = async (sessionId: string) => {
    const session = client.getSession(sessionId);
    if (session) {
      // Revoke tokens from Okta
      await client.revokeTokens(
        session.tokens.accessToken,
        session.tokens.refreshToken
      );

      // Remove local session
      client.removeSession(sessionId);
      console.log('User logged out successfully');
    }
  };

  return { getSessionInfo, logout };
}

// Example 5: Express.js middleware integration
function createExpressMiddleware() {
  return async (req: any, res: any, next: any) => {
    const { middleware } = await initializeOktaClient();
    const sessionId = req.cookies?.sessionId || req.headers['x-session-id'];

    if (!sessionId) {
      return res.status(401).json({ error: 'No session provided' });
    }

    try {
      const auth = await middleware.withValidToken(sessionId);

      if (!auth.isValid) {
        return res.status(401).json({ error: auth.error });
      }

      // Attach user info and auth headers to request
      req.user = auth.user;
      req.authHeaders = auth.headers;
      next();
    } catch (error) {
      console.error('Authentication middleware error:', error);
      res.status(500).json({ error: 'Authentication failed' });
    }
  };
}

// Example 6: Device flow for CLI applications
async function deviceFlowExample() {
  // Note: This is a simplified example. Okta device flow requires additional setup
  const { client } = await initializeOktaClient();

  console.log('For CLI applications, you might want to:');
  console.log('1. Use device authorization flow');
  console.log('2. Open browser for user authentication');
  console.log('3. Poll for token completion');

  // Generate auth URL for device flow
  const { url: authUrl } = await client.generateAuthUrl();
  console.log('Open this URL in your browser:', authUrl);
}

// Example 7: Token refresh testing
async function testTokenRefresh(sessionId: string) {
  const { client } = await initializeOktaClient();

  const session = client.getSession(sessionId);
  if (!session) {
    throw new Error('Invalid session');
  }

  console.log('Original token expires at:', new Date(session.tokens.expiresAt));

  try {
    // Force token refresh
    const newTokens = await client.refreshAccessToken(session.tokens.refreshToken);
    console.log('Token refreshed successfully');
    console.log('New token expires at:', new Date(newTokens.expiresAt));

    // Update session with new tokens
    session.tokens = newTokens;
    return newTokens;
  } catch (error) {
    console.error('Token refresh failed:', error);
    throw error;
  }
}

// Export examples for use
export {
  initializeOktaClient,
  webAppOAuthFlow,
  makeAuthenticatedAPIRequest,
  sessionManagementExample,
  createExpressMiddleware,
  deviceFlowExample,
  testTokenRefresh
};

// Example usage in a simple script
async function main() {
  try {
    console.log('=== Okta OAuth Library Examples ===\n');

    // Initialize client
    console.log('1. Initializing Okta client...');
    const { client } = await initializeOktaClient();
    console.log('✓ Client initialized\n');

    // Generate auth URL
    console.log('2. Generating authorization URL...');
    const { url: authUrl, pkce } = await client.generateAuthUrl('example-state');
    console.log('✓ Authorization URL:', authUrl);
    console.log('✓ PKCE Code Verifier stored for callback\n');

    console.log('3. Next steps:');
    console.log('   - Redirect user to authorization URL');
    console.log('   - Handle callback with authorization code');
    console.log('   - Exchange code for tokens using PKCE verifier');
    console.log('   - Create user session');
    console.log('   - Make authenticated API requests\n');

  } catch (error) {
    console.error('Example failed:', error);
  }
}

// Run example if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}
