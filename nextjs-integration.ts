/**
 * Next.js Integration Example for Okta OAuth Library
 * Demonstrates how to use the library in a Next.js application
 */

import { NextApiRequest, NextApiResponse } from 'next';
import { createOktaClient, OktaConfigHelper } from '../ai_flow_auth';

// Initialize Okta client (singleton pattern)
let oktaInstance: ReturnType<typeof createOktaClient> | null = null;

function getOktaInstance() {
  if (!oktaInstance) {
    const config = OktaConfigHelper.fromEnv();
    oktaInstance = createOktaClient(config);
  }
  return oktaInstance;
}

// API Route: /api/auth/login
export async function loginHandler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { client } = getOktaInstance();
    const state = req.query.state as string || Math.random().toString(36);

    const { url: authUrl, pkce } = await client.generateAuthUrl(state);

    // Store PKCE verifier in session/cookie for callback
    res.setHeader('Set-Cookie', [
      `pkce_verifier=${pkce.codeVerifier}; HttpOnly; Secure; SameSite=Strict; Path=/`,
      `oauth_state=${state}; HttpOnly; Secure; SameSite=Strict; Path=/`
    ]);

    res.json({ authUrl });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
}

// API Route: /api/auth/callback
export async function callbackHandler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { client } = getOktaInstance();
    const { code, state } = req.query;

    if (!code) {
      return res.status(400).json({ error: 'Authorization code missing' });
    }

    // Extract PKCE verifier from cookies
    const cookies = parseCookies(req.headers.cookie || '');
    const codeVerifier = cookies.pkce_verifier;
    const storedState = cookies.oauth_state;

    if (!codeVerifier) {
      return res.status(400).json({ error: 'PKCE verifier missing' });
    }

    if (state !== storedState) {
      return res.status(400).json({ error: 'State parameter mismatch' });
    }

    // Exchange code for tokens
    const tokens = await client.exchangeCodeForTokens(code as string, codeVerifier);

    // Create user session
    const sessionId = await client.createSession(tokens);

    // Set session cookie
    res.setHeader('Set-Cookie', [
      `session_id=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`,
      'pkce_verifier=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0', // Clear PKCE
      'oauth_state=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'    // Clear state
    ]);

    // Redirect to dashboard or return session info
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Callback error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
}

// API Route: /api/auth/logout
export async function logoutHandler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { client } = getOktaInstance();
    const cookies = parseCookies(req.headers.cookie || '');
    const sessionId = cookies.session_id;

    if (sessionId) {
      const session = client.getSession(sessionId);
      if (session) {
        // Revoke tokens
        await client.revokeTokens(
          session.tokens.accessToken,
          session.tokens.refreshToken
        );

        // Remove session
        client.removeSession(sessionId);
      }
    }

    // Clear session cookie
    res.setHeader('Set-Cookie',
      'session_id=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
}

// API Route: /api/user/profile
export async function profileHandler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { middleware } = getOktaInstance();
    const cookies = parseCookies(req.headers.cookie || '');
    const sessionId = cookies.session_id;

    if (!sessionId) {
      return res.status(401).json({ error: 'No session found' });
    }

    const auth = await middleware.withValidToken(sessionId);

    if (!auth.isValid) {
      return res.status(401).json({ error: auth.error });
    }

    res.json({ user: auth.user });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to get user profile' });
  }
}

// API Route: /api/proxy/[...path] - Proxy authenticated requests to backend
export async function proxyHandler(req: NextApiRequest, res: NextApiResponse) {
  try {
    const { middleware } = getOktaInstance();
    const cookies = parseCookies(req.headers.cookie || '');
    const sessionId = cookies.session_id;

    if (!sessionId) {
      return res.status(401).json({ error: 'No session found' });
    }

    // Build target URL
    const pathArray = req.query.path as string[];
    const targetPath = pathArray.join('/');
    const targetUrl = `${process.env.BACKEND_API_URL}/${targetPath}`;

    // Add query parameters
    const queryString = new URLSearchParams(req.query as Record<string, string>).toString();
    const fullUrl = queryString ? `${targetUrl}?${queryString}` : targetUrl;

    // Proxy request with authentication
    const response = await middleware.proxyRequest(sessionId, fullUrl, {
      method: req.method,
      body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined,
      headers: {
        'Content-Type': 'application/json',
        ...req.headers
      }
    });

    const data = await response.json();
    res.status(response.status).json(data);
  } catch (error) {
    console.error('Proxy error:', error);
    res.status(500).json({ error: 'Proxy request failed' });
  }
}

// Middleware for protecting pages/API routes
export function withAuth(handler: (req: NextApiRequest, res: NextApiResponse) => Promise<void>) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    try {
      const { middleware } = getOktaInstance();
      const cookies = parseCookies(req.headers.cookie || '');
      const sessionId = cookies.session_id;

      if (!sessionId) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const auth = await middleware.withValidToken(sessionId);

      if (!auth.isValid) {
        return res.status(401).json({ error: auth.error });
      }

      // Attach user to request
      (req as any).user = auth.user;
      (req as any).authHeaders = auth.headers;

      return handler(req, res);
    } catch (error) {
      console.error('Auth middleware error:', error);
      res.status(500).json({ error: 'Authentication failed' });
    }
  };
}

// React Hook for client-side authentication
export function useOktaAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const login = async () => {
    try {
      const response = await fetch('/api/auth/login');
      const data = await response.json();

      if (data.authUrl) {
        window.location.href = data.authUrl;
      }
    } catch (err) {
      setError('Login failed');
    }
  };

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      setUser(null);
      window.location.href = '/';
    } catch (err) {
      setError('Logout failed');
    }
  };

  const fetchProfile = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/user/profile');

      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
      } else {
        setUser(null);
      }
    } catch (err) {
      setError('Failed to fetch profile');
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  return {
    user,
    loading,
    error,
    login,
    logout,
    refetch: fetchProfile
  };
}

// Utility function to parse cookies
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};

  cookieHeader.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });

  return cookies;
}

// Export all handlers for Next.js API routes
export {
  getOktaInstance,
  parseCookies
};
