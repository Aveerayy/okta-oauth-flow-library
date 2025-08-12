# Okta OAuth Flow Library

A comprehensive, reusable TypeScript library for implementing Okta OAuth authentication with PKCE, session management, and automatic token refresh capabilities. Perfect for Next.js applications and MCP client/server setups.

## Features

- ✅ **OAuth 2.0 + PKCE**: Secure authorization code flow with Proof Key for Code Exchange
- ✅ **Session Management**: In-memory session storage with user information
- ✅ **Automatic Token Refresh**: Transparent token renewal before expiration
- ✅ **Middleware Support**: Easy integration with API routes and request proxying
- ✅ **TypeScript First**: Full type safety and IntelliSense support
- ✅ **Next.js Ready**: Built-in integration examples for Next.js applications
- ✅ **Flexible Configuration**: Environment-based or manual configuration

## Quick Start

### 1. Installation

```bash
npm install node-fetch @types/node-fetch
# or
yarn add node-fetch @types/node-fetch
```

### 2. Environment Setup

Copy `.env.example` to `.env.local` and configure:

```env
OKTA_CLIENT_ID=your-okta-client-id
OKTA_CLIENT_SECRET=your-okta-client-secret
OKTA_ISSUER=https://dev-123456.okta.com/oauth2/default
OKTA_REDIRECT_URI=http://localhost:3000/api/auth/callback
```

### 3. Basic Usage

```typescript
import { createOktaClient, OktaConfigHelper } from './ai_flow_auth';

// Initialize client
const config = OktaConfigHelper.fromEnv();
const { client, middleware } = createOktaClient(config);

// Generate auth URL
const { url: authUrl, pkce } = await client.generateAuthUrl();
console.log('Redirect user to:', authUrl);

// Handle callback
const tokens = await client.exchangeCodeForTokens(code, pkce.codeVerifier);
const sessionId = await client.createSession(tokens);

// Make authenticated requests
const response = await middleware.proxyRequest(
  sessionId,
  'https://api.backend.com/data'
);
```

## API Reference

### Core Classes

#### `OktaOAuthClient`

Main client for OAuth operations:

- `generateAuthUrl(state?, pkce?)` - Generate authorization URL with PKCE
- `exchangeCodeForTokens(code, verifier)` - Exchange auth code for tokens
- `refreshAccessToken(refreshToken)` - Refresh expired access token
- `getUserInfo(accessToken)` - Get user profile information
- `createSession(tokens)` - Create new user session
- `getSession(sessionId)` - Retrieve session by ID
- `removeSession(sessionId)` - Delete session
- `ensureValidToken(sessionId)` - Validate/refresh token automatically
- `revokeTokens(accessToken, refreshToken?)` - Logout and revoke tokens

#### `OktaMiddleware`

Authentication middleware for requests:

- `withValidToken(sessionId)` - Validate session and get auth headers
- `proxyRequest(sessionId, url, options?)` - Make authenticated HTTP requests

#### `PKCEHelper`

PKCE code generation utilities:

- `generateCodeVerifier()` - Generate random code verifier
- `generateCodeChallenge(verifier)` - Generate SHA256 code challenge
- `generatePKCEPair()` - Generate both verifier and challenge

### Configuration

```typescript
interface OktaConfig {
  clientId: string;
  clientSecret: string;
  issuer: string;
  redirectUri: string;
  scopes?: string[]; // Default: ['openid', 'profile', 'email']
}
```

## Next.js Integration

### API Routes

Create these API routes in your Next.js app:

```
pages/api/auth/
├── login.ts      # Initiate OAuth flow
├── callback.ts   # Handle OAuth callback
└── logout.ts     # Logout user

pages/api/
├── user/profile.ts    # Get user profile
└── proxy/[...path].ts # Proxy authenticated requests
```

### Protected API Route Example

```typescript
import { withAuth } from '../../../nextjs-integration';

export default withAuth(async (req, res) => {
  // req.user contains authenticated user info
  // req.authHeaders contains authorization headers
  
  res.json({ message: 'Protected data', user: req.user });
});
```

### React Hook

```typescript
import { useOktaAuth } from '../../../nextjs-integration';

function MyComponent() {
  const { user, loading, login, logout } = useOktaAuth();

  if (loading) return <div>Loading...</div>;
  
  return (
    <div>
      {user ? (
        <div>
          <p>Welcome, {user.name}!</p>
          <button onClick={logout}>Logout</button>
        </div>
      ) : (
        <button onClick={login}>Login with Okta</button>
      )}
    </div>
  );
}
```

## MCP Server Integration

### Backend Proxy Example

```typescript
// Proxy all requests to your MCP server with authentication
app.use('/api/mcp/*', async (req, res) => {
  const sessionId = req.cookies.session_id;
  const { middleware } = getOktaInstance();
  
  try {
    const mcpResponse = await middleware.proxyRequest(
      sessionId,
      `${MCP_SERVER_URL}${req.path}`,
      {
        method: req.method,
        body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined
      }
    );
    
    const data = await mcpResponse.json();
    res.status(mcpResponse.status).json(data);
  } catch (error) {
    res.status(401).json({ error: 'Authentication failed' });
  }
});
```

## Advanced Usage

### Custom Session Storage

```typescript
class CustomOktaClient extends OktaOAuthClient {
  private sessionStore: DatabaseSessionStore;

  async createSession(tokens: TokenResponse): Promise<string> {
    const userInfo = await this.getUserInfo(tokens.accessToken);
    const sessionId = this.generateSessionId();
    
    await this.sessionStore.save(sessionId, {
      user: userInfo,
      tokens,
      createdAt: new Date(),
      expiresAt: new Date(tokens.expiresAt)
    });
    
    return sessionId;
  }
}
```

### Token Refresh Monitoring

```typescript
client.on('tokenRefresh', (sessionId, newTokens) => {
  console.log(`Tokens refreshed for session ${sessionId}`);
  // Update database, notify other services, etc.
});
```

## Error Handling

The library throws descriptive errors for common scenarios:

```typescript
try {
  const tokens = await client.exchangeCodeForTokens(code, verifier);
} catch (error) {
  if (error.message.includes('Token exchange failed')) {
    // Handle OAuth errors (invalid code, expired, etc.)
  } else if (error.message.includes('Token refresh failed')) {
    // Handle refresh token expiration
    // Redirect to login
  }
}
```

## Security Considerations

1. **PKCE**: Always use PKCE for public clients
2. **State Parameter**: Validate state parameter to prevent CSRF
3. **Secure Cookies**: Use HttpOnly, Secure, SameSite cookies
4. **Token Storage**: Never store tokens in localStorage
5. **HTTPS**: Always use HTTPS in production
6. **Token Rotation**: Refresh tokens before expiration

## Files Structure

```
├── ai_flow_auth.ts          # Main library implementation
├── okta-example-usage.ts    # Usage examples and documentation
├── nextjs-integration.ts    # Next.js specific integration
├── package.json            # Dependencies and scripts
├── .env.example            # Environment variables template
└── README.md              # This documentation
```

## TypeScript Support

Full TypeScript support with proper interfaces:

```typescript
import {
  OktaConfig,
  TokenResponse,
  UserSession,
  PKCECodePair,
  AuthenticatedRequest
} from './ai_flow_auth';
```

## Testing

Run the example usage:

```bash
npm run dev
```

Build and type-check:

```bash
npm run build
npm run type-check
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

---

## Troubleshooting

### Common Issues

**"Token exchange failed"**
- Verify client ID and secret
- Check redirect URI matches exactly
- Ensure PKCE verifier is correctly stored and retrieved

**"Token refresh failed"**
- Refresh token may have expired
- Check if refresh tokens are being rotated
- Verify client has refresh token grant type enabled

**"Authentication failed"**
- Session may have expired
- Token may have been revoked
- Check network connectivity to Okta

### Debug Mode

Enable debug logging:

```typescript
const { client } = createOktaClient({
  ...config,
  debug: true
});
```

For support, please open an issue in the repository.
