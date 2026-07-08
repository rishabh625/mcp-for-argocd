import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import express from 'express';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { logger } from '../logging/logging.js';
import { createServer } from './server.js';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { getDefaultServer, loadToken, isTokenExpired, saveToken } from '../auth/token-store.js';
import { createTokenRefreshProvider } from '../auth/token-refresh.js';
import { fetchOIDCProviderMetadata } from '../auth/settings.js';
import { refreshAccessToken, generateState, generatePKCEChallenge } from '../auth/oauth.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { ArgocdOAuthProvider } from '../auth/mcp-oauth-provider.js';
import type { StoredAuth } from '../auth/types.js';
import { getIAPUser, validateIAP } from '../auth/iap.js';
import { tokenRegistryFromEnv } from './tokenRegistry.js';

// Load the base-URL -> token registry once at startup from the JSON file at
// ARGOCD_TOKEN_REGISTRY_PATH. Shared across all connections; read-only after
// construction.
const tokenRegistry = tokenRegistryFromEnv();

interface AuthConfig {
  baseUrl: string;
  apiToken: string;
  /** Whether this auth comes from SSO (stored token with refresh capability) */
  isSSOAuth: boolean;
}

/**
 * Attempt to refresh an expired token at startup
 * Returns the new access token if successful, null otherwise
 */
async function tryRefreshExpiredToken(storedAuth: StoredAuth): Promise<string | null> {
  // First, try token refresh if we have a refresh token
  if (storedAuth.token.refreshToken) {
    try {
      logger.info(
        { serverUrl: storedAuth.serverUrl },
        'Token expired, attempting refresh at startup...'
      );

      // Try with stored OIDC config first
      let providerMetadata = await fetchOIDCProviderMetadata(storedAuth.oidcConfig);
      let oidcConfig = storedAuth.oidcConfig;

      try {
        const newToken = await refreshAccessToken(
          providerMetadata,
          oidcConfig,
          storedAuth.token.refreshToken
        );
        await saveToken(storedAuth.serverUrl, newToken, oidcConfig);
        logger.info({ serverUrl: storedAuth.serverUrl }, 'Token refreshed successfully at startup');
        return newToken.accessToken;
      } catch {
        // If refresh fails, try re-fetching OIDC settings from server (config may have changed)
        logger.debug(
          { serverUrl: storedAuth.serverUrl },
          'Refresh with stored config failed, re-fetching OIDC settings...'
        );

        const { fetchOIDCSettings } = await import('../auth/settings.js');
        oidcConfig = await fetchOIDCSettings(storedAuth.serverUrl);
        providerMetadata = await fetchOIDCProviderMetadata(oidcConfig);

        const newToken = await refreshAccessToken(
          providerMetadata,
          oidcConfig,
          storedAuth.token.refreshToken
        );
        await saveToken(storedAuth.serverUrl, newToken, oidcConfig);
        logger.info(
          { serverUrl: storedAuth.serverUrl },
          'Token refreshed successfully with updated OIDC config'
        );
        return newToken.accessToken;
      }
    } catch (error) {
      logger.warn(
        {
          serverUrl: storedAuth.serverUrl,
          error: error instanceof Error ? error.message : String(error)
        },
        'Token refresh failed'
      );
    }
  } else {
    logger.debug({ serverUrl: storedAuth.serverUrl }, 'No refresh token available');
  }

  return null;
}

/**
 * Resolve authentication credentials from environment variables or stored tokens
 */
async function resolveAuth(options?: { serverUrl?: string }): Promise<AuthConfig | null> {
  // Priority 1: Environment variables
  const envBaseUrl = process.env.ARGOCD_BASE_URL || '';
  const envApiToken = process.env.ARGOCD_API_TOKEN || '';

  if (envBaseUrl && envApiToken) {
    logger.info('Using authentication from environment variables');
    return { baseUrl: envBaseUrl, apiToken: envApiToken, isSSOAuth: false };
  }

  // Priority 2: Stored token for specific server
  if (options?.serverUrl) {
    const storedAuth = await loadToken(options.serverUrl);
    if (storedAuth) {
      let accessToken = storedAuth.token.accessToken;

      if (isTokenExpired(storedAuth.token)) {
        // Try to refresh the expired token
        const refreshedToken = await tryRefreshExpiredToken(storedAuth);
        if (refreshedToken) {
          accessToken = refreshedToken;
        } else {
          logger.warn(
            { serverUrl: options.serverUrl },
            'Stored token is expired and refresh failed. Please run `argocd-mcp login` to re-authenticate.'
          );
          return null;
        }
      }

      logger.info({ serverUrl: options.serverUrl }, 'Using stored authentication token');
      return {
        baseUrl: storedAuth.serverUrl,
        apiToken: accessToken,
        isSSOAuth: true
      };
    }
    logger.warn({ serverUrl: options.serverUrl }, 'No stored authentication found for server');
    return null;
  }

  // Priority 3: Default stored token (first stored server)
  const defaultAuth = await getDefaultServer();
  if (defaultAuth) {
    let accessToken = defaultAuth.token.accessToken;

    if (isTokenExpired(defaultAuth.token)) {
      // Try to refresh the expired token
      const refreshedToken = await tryRefreshExpiredToken(defaultAuth);
      if (refreshedToken) {
        accessToken = refreshedToken;
      } else {
        logger.warn(
          { serverUrl: defaultAuth.serverUrl },
          'Stored token is expired and refresh failed. Please run `argocd-mcp login` to re-authenticate.'
        );
        return null;
      }
    }

    logger.info({ serverUrl: defaultAuth.serverUrl }, 'Using default stored authentication token');
    return {
      baseUrl: defaultAuth.serverUrl,
      apiToken: accessToken,
      isSSOAuth: true
    };
  }

  return null;
}

export const connectStdioTransport = async () => {
  const auth = await resolveAuth();

  // Start server even without auth - tools will report auth errors gracefully
  const tokenRefreshProvider = auth?.isSSOAuth
    ? createTokenRefreshProvider(auth.baseUrl)
    : undefined;

  const server = createServer({
    argocdBaseUrl: auth?.baseUrl ?? '',
    argocdApiToken: auth?.apiToken ?? '',
    tokenRefreshProvider,
    isAuthenticated: auth !== null,
    tokenRegistry
  });

  logger.info('Connecting to stdio transport');
  await server.connect(new StdioServerTransport());
};

export const connectSSETransport = (port: number) => {
  const app = express();
  const transports: { [sessionId: string]: SSEServerTransport } = {};

  app.get('/sse', async (req, res) => {
    const server = createServer({
      argocdBaseUrl: (req.headers['x-argocd-base-url'] as string) || '',
      argocdApiToken: (req.headers['x-argocd-api-token'] as string) || '',
      tokenRegistry
    });

    const transport = new SSEServerTransport('/messages', res);
    transports[transport.sessionId] = transport;
    res.on('close', () => {
      delete transports[transport.sessionId];
    });
    await server.connect(transport);
  });

  app.post('/messages', async (req, res) => {
    const sessionId = req.query.sessionId as string;
    const transport = transports[sessionId];
    if (transport) {
      await transport.handlePostMessage(req, res);
    } else {
      res.status(400).send(`No transport found for sessionId: ${sessionId}`);
    }
  });

  logger.info(`Connecting to SSE transport on port: ${port}`);
  app.listen(port);
};

// Resolve the session-level ArgoCD credentials from headers or env.
//
// The API token is only ever accepted here (x-argocd-api-token header or
// ARGOCD_API_TOKEN env var) — never as a tool-call argument — so the secret
// stays in the transport layer and out of prompts/model context.
//
// The token is normally MANDATORY and the connection is rejected when it is
// missing. The exception is when a token registry (ARGOCD_TOKEN_REGISTRY_PATH)
// is configured: the per-call base URL can then resolve its token from the
// registry, so a tokenless connection is allowed.
//
// The base URL is optional at this level: when it is absent, callers may supply
// it per call via the argocdBaseUrl tool argument.
const resolveCredentials = (
  req: express.Request,
  res: express.Response
): { argocdBaseUrl: string; argocdApiToken: string } | null => {
  const argocdBaseUrl =
    (req.headers['x-argocd-base-url'] as string) || process.env.ARGOCD_BASE_URL || '';
  const argocdApiToken =
    (req.headers['x-argocd-api-token'] as string) || process.env.ARGOCD_API_TOKEN || '';
  if (!argocdApiToken && tokenRegistry.getSize() === 0) {
    res
      .status(400)
      .send(
        'x-argocd-api-token must be provided in the request header (or the ARGOCD_API_TOKEN env var), ' +
          'or a token registry must be configured via ARGOCD_TOKEN_REGISTRY_PATH.'
      );
    return null;
  }
  return { argocdBaseUrl, argocdApiToken };
};

export const connectHttpTransport = (
  port: number,
  options: {
    serverUrl?: string;
    insecure?: boolean;
    callbackPort?: number;
    mcpUrl?: string;
    stateless?: boolean;
  } = {}
) => {
  const stateless = options.stateless ?? false;
  // Assigned in OAuth mode (serverUrl set) and exposed here so the shared
  // handleSessionRequest (registered below for all modes) can reach it.
  let oauthProvider: ArgocdOAuthProvider | undefined;

  // Public path prefix under which this server is exposed behind an ingress
  // (e.g. "/argocd"), derived from the advertised MCP URL. Used to rewrite the
  // OAuth authorization-server metadata when the upstream router is unaware of
  // the prefix. Empty when the server is exposed at the root (no rewriting).
  let pathPrefix = '';
  try {
    const mcpUrlForPrefix = options.mcpUrl || process.env.MCP_URL || '';
    if (mcpUrlForPrefix) {
      const p = new URL(mcpUrlForPrefix).pathname.replace(/\/+$/, '');
      if (p && p !== '/') pathPrefix = p;
    }
  } catch {
    // Ignore a malformed MCP URL; fall back to no prefix rewriting.
  }

  const app = express();
  app.use(express.json());

  app.get('/healthz', (_, res) => {
    res.status(200).json({ status: 'ok' });
  });

  // Request logger for debugging
  app.use((req, res, next) => {
    logger.info({ method: req.method, url: req.url, headers: req.headers }, 'Incoming request');

    // Rewrite metadata response to include the path prefix
    if (req.url.endsWith('/.well-known/oauth-authorization-server')) {
      const oldJson = res.json;
      res.json = function (data) {
        if (data && typeof data === 'object') {
          const prefix = pathPrefix;
          const keys = [
            'authorization_endpoint',
            'token_endpoint',
            'registration_endpoint',
            'introspection_endpoint',
            'revocation_endpoint'
          ];
          for (const key of keys) {
            if (data[key] && typeof data[key] === 'string' && !data[key].includes(prefix)) {
              try {
                const url = new URL(data[key]);
                url.pathname = prefix + (url.pathname === '/' ? '' : url.pathname);
                data[key] = url.toString();
              } catch (e) {
                logger.warn({ error: e, key, value: data[key] }, 'Failed to rewrite metadata URL');
              }
            }
          }
        }
        return oldJson.apply(res, arguments as any);
      };
    }

    const oldSend = res.send;
    res.send = function (data) {
      logger.info(
        {
          method: req.method,
          url: req.url,
          statusCode: res.statusCode,
          headers: res.getHeaders(),
          body: data?.toString().substring(0, 500)
        },
        'Sending response'
      );
      return oldSend.apply(res, arguments as any);
    };
    const oldJson = res.json;
    res.json = function (data) {
      logger.info(
        {
          method: req.method,
          url: req.url,
          statusCode: res.statusCode,
          headers: res.getHeaders(),
          body: JSON.stringify(data).substring(0, 500)
        },
        'Sending JSON response'
      );
      return oldJson.apply(res, arguments as any);
    };
    next();
  });

  const httpTransports: { [sessionId: string]: StreamableHTTPServerTransport } = {};

  if (options?.serverUrl) {
    // OAuth 2.1 mode: MCP clients authenticate via OAuth flow proxied to ArgoCD OIDC
    const callbackPort = options.callbackPort ?? 8085;
    let mcpBaseUrl = options.mcpUrl || process.env.MCP_URL || `http://localhost:${port}`;
    if (!mcpBaseUrl.endsWith('/')) {
      mcpBaseUrl += '/';
    }
    const provider = new ArgocdOAuthProvider(
      options.serverUrl,
      callbackPort,
      options.insecure,
      mcpBaseUrl
    );
    oauthProvider = provider;

    // Install OAuth routes (/.well-known/oauth-authorization-server, /authorize, /token, /register)
    // Mount at root to ensure correct path matching for /.well-known endpoints
    app.use(
      mcpAuthRouter({
        provider,
        issuerUrl: new URL(mcpBaseUrl),
        baseUrl: new URL(mcpBaseUrl)
      })
    );

    // OAuth callback route merged into main app for single-port environments
    app.get(['/auth/callback', '/mcp/auth/callback'], async (req, res) => {
      const code = req.query.code as string;
      const state = req.query.state as string;
      const error = req.query.error as string;
      const errorDescription = req.query.error_description as string;

      if (error) {
        logger.error({ error, errorDescription }, 'Upstream OIDC authentication failed');
        res.status(400).send(`Authentication failed: ${errorDescription || error}`);
        return;
      }

      if (!code || !state) {
        res.status(400).send('Missing code or state parameter');
        return;
      }

      try {
        const iapUser = getIAPUser(req.headers);
        const redirectUrl = await provider.handleUpstreamCallback(code, state, iapUser?.email);
        res.redirect(redirectUrl);
      } catch (err) {
        logger.error(
          { error: err instanceof Error ? err.message : String(err) },
          'Failed to handle upstream callback'
        );
        res.status(500).send('Authentication callback failed. Please try again.');
      }
    });

    // Protect /mcp with bearer auth
    const iapToBearer = (
      req: express.Request,
      _res: express.Response,
      next: express.NextFunction
    ) => {
      if (!req.headers.authorization) {
        const iapUser = getIAPUser(req.headers);
        if (iapUser) {
          const token = provider.getAccessTokenByEmail(iapUser.email);
          if (token) {
            logger.debug({ email: iapUser.email }, 'Injected bearer token from IAP identity');
            req.headers.authorization = `Bearer ${token}`;
          }
        }
      }
      next();
    };

    const bearerAuth = requireBearerAuth({ verifier: provider });

    app.post(
      ['/', '/mcp'],
      iapToBearer,
      (req, res, next) => {
        // Priority 1: Bearer token in header (OAuth flow)
        if (req.headers.authorization) {
          return bearerAuth(req, res, next);
        }

        // Priority 2: Fallback to environment variable (Token-based auth)
        if (process.env.ARGOCD_API_TOKEN && process.env.ARGOCD_BASE_URL) {
          logger.debug('No authorization header, falling back to environment variables');
          (req as any).auth = {
            extra: {
              argocdToken: process.env.ARGOCD_API_TOKEN,
              argocdBaseUrl: process.env.ARGOCD_BASE_URL
            }
          };
          return next();
        }

        // Priority 3: Allow unauthenticated initialization
        // This allows the connection to be established so the client can see auth capabilities.
        if (isInitializeRequest(req.body)) {
          logger.debug('Allowing unauthenticated initialization handshake');
          return next();
        }

        // No auth available, trigger OAuth flow for everything else
        return bearerAuth(req, res, next);
      },
      async (req, res) => {
        const sessionIdFromHeader = req.headers['mcp-session-id'] as string | undefined;
        let transport: StreamableHTTPServerTransport;

        if (sessionIdFromHeader && httpTransports[sessionIdFromHeader]) {
          transport = httpTransports[sessionIdFromHeader];
        } else if (!sessionIdFromHeader && isInitializeRequest(req.body)) {
          // Extract ArgoCD credentials from the verified OAuth token
          const argocdToken = req.auth?.extra?.argocdToken as string;
          const argocdBaseUrl = (req.auth?.extra?.argocdBaseUrl as string) || options.serverUrl!;

          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (newSessionId) => {
              httpTransports[newSessionId] = transport;
            }
          });

          transport.onclose = () => {
            if (transport.sessionId) {
              delete httpTransports[transport.sessionId];
            }
          };

          const server = createServer({
            argocdBaseUrl,
            argocdApiToken: argocdToken,
            isAuthenticated: !!argocdToken,
            tokenRegistry
          });

          await server.connect(transport);
        } else {
          const errorMsg = sessionIdFromHeader
            ? `Invalid or expired session ID: ${sessionIdFromHeader}`
            : 'Bad Request: Not an initialization request and no valid session ID provided.';
          res.status(400).json({
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: errorMsg
            },
            id: req.body?.id !== undefined ? req.body.id : null
          });
          return;
        }

        await transport.handleRequest(req, res, req.body);
      }
    );

    logger.info(
      { serverUrl: options.serverUrl, port },
      'OAuth 2.1 authentication enabled for HTTP transport'
    );
  } else {
    // Header/registry-based auth (no OAuth). Supports the ARGOCD_TOKEN_REGISTRY
    // (multi-instance) and stateless mode for multi-replica (HPA) deployments.
    const handleMcpPost = async (req: express.Request, res: express.Response) => {
      const sessionIdFromHeader = req.headers['mcp-session-id'] as string | undefined;
      let transport: StreamableHTTPServerTransport;

      if (!stateless && sessionIdFromHeader && httpTransports[sessionIdFromHeader]) {
        transport = httpTransports[sessionIdFromHeader];
      } else if (stateless || (!sessionIdFromHeader && isInitializeRequest(req.body))) {
        const credentials = resolveCredentials(req, res);
        if (!credentials) return;

        transport = new StreamableHTTPServerTransport(
          stateless
            ? { sessionIdGenerator: undefined }
            : {
                sessionIdGenerator: () => randomUUID(),
                onsessioninitialized: (newSessionId) => {
                  httpTransports[newSessionId] = transport;
                }
              }
        );

        if (!stateless) {
          transport.onclose = () => {
            if (transport.sessionId) delete httpTransports[transport.sessionId];
          };
        }

        // Enable SSO token refresh when a stored token exists for this base URL.
        const storedAuth = credentials.argocdBaseUrl
          ? await loadToken(credentials.argocdBaseUrl)
          : null;
        const tokenRefreshProvider =
          storedAuth && credentials.argocdBaseUrl
            ? createTokenRefreshProvider(credentials.argocdBaseUrl)
            : undefined;

        const server = createServer({
          ...credentials,
          tokenRefreshProvider,
          tokenRegistry
        });

        await server.connect(transport);
      } else {
        const errorMsg = sessionIdFromHeader
          ? `Invalid or expired session ID: ${sessionIdFromHeader}`
          : 'Bad Request: Not an initialization request and no valid session ID provided.';
        res.status(400).json({
          jsonrpc: '2.0',
          error: {
            code: -32000,
            message: errorMsg
          },
          id: req.body?.id !== undefined ? req.body.id : null
        });
        return;
      }

      await transport.handleRequest(req, res, req.body);
    };

    app.post(['/', '/mcp'], handleMcpPost);
  }

  const handleSessionRequest = async (req: express.Request, res: express.Response) => {
    if (stateless) {
      res.status(405).send('Method Not Allowed in stateless mode');
      return;
    }
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (!sessionId || !httpTransports[sessionId]) {
      // Handle browser visits to /mcp or /
      if (
        req.method === 'GET' &&
        options.serverUrl &&
        !req.headers['mcp-session-id'] &&
        req.accepts('html')
      ) {
        const iapUser = getIAPUser(req.headers);
        const token = iapUser ? oauthProvider?.getAccessTokenByEmail(iapUser.email) : undefined;

        if (token) {
          res.send(`
            <!DOCTYPE html>
            <html>
              <head>
                <title>ArgoCD MCP Server</title>
                <style>
                  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 2rem; background: #f4f7f9; }
                  .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                  h1 { color: #00a0e9; margin-top: 0; }
                  code { background: #eee; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; word-break: break-all; }
                  .success-icon { color: #28a745; font-size: 3rem; margin-bottom: 1rem; }
                  .info { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #eee; font-size: 0.9rem; color: #666; }
                </style>
              </head>
              <body>
                <div class="card">
                  <div class="success-icon">✅</div>
                  <h1>Connected to ArgoCD</h1>
                  <p>Authenticated as: <strong>${iapUser?.email}</strong></p>
                  <p>Your ArgoCD account is successfully linked to this MCP server via IAP.</p>
                  <p>You can now use this server in your MCP client (e.g. Cursor or VS Code).</p>
                  
                  <h3>MCP Configuration</h3>
                  <p>Use the following endpoint URL in your client:</p>
                  <code>${options.mcpUrl ? options.mcpUrl + '/mcp' : req.protocol + '://' + req.get('host') + '/mcp'}</code>
                  
                  <div class="info">
                    <p>Connected to ArgoCD at: <a href="${options.serverUrl}" target="_blank">${options.serverUrl}</a></p>
                  </div>
                </div>
              </body>
            </html>
          `);
          return;
        }

        // If we land back with a code, it means we just completed the flow
        if (req.query.code) {
          res.send(`
            <!DOCTYPE html>
            <html>
              <head>
                <title>ArgoCD MCP Server</title>
                <style>
                  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 2rem; background: #f4f7f9; }
                  .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                  h1 { color: #00a0e9; margin-top: 0; }
                  .success-icon { color: #28a745; font-size: 3rem; margin-bottom: 1rem; }
                </style>
              </head>
              <body>
                <div class="card">
                  <div class="success-icon">✅</div>
                  <h1>Authentication Successful</h1>
                  <p>You have successfully authenticated with ArgoCD.</p>
                  ${iapUser ? '<p>Redirecting to status page...</p><script>setTimeout(() => window.location.href = window.location.pathname, 2000);</script>' : '<p>You can now use this server in your MCP client.</p>'}
                </div>
              </body>
            </html>
          `);
          return;
        }

        // Redirect to OAuth authorization endpoint using the 'web' client
        const mcpBaseUrl = options.mcpUrl || `${req.protocol}://${req.get('host')}`;
        const authorizeUrl = new URL(`${mcpBaseUrl}/authorize`);
        authorizeUrl.searchParams.set('client_id', 'web');
        authorizeUrl.searchParams.set('response_type', 'code');
        authorizeUrl.searchParams.set('redirect_uri', `${mcpBaseUrl}/mcp`);
        authorizeUrl.searchParams.set('state', generateState());

        const pkce = generatePKCEChallenge();
        authorizeUrl.searchParams.set('code_challenge', pkce.codeChallenge);
        authorizeUrl.searchParams.set('code_challenge_method', pkce.codeChallengeMethod);

        logger.info(
          { email: iapUser?.email },
          'Redirecting unauthenticated browser request to OAuth flow'
        );
        res.redirect(authorizeUrl.toString());
        return;
      }

      res.status(400).send('Invalid or missing session ID');
      return;
    }
    await httpTransports[sessionId].handleRequest(req, res);
  };

  app.get(['/', '/mcp'], handleSessionRequest);
  app.delete(['/', '/mcp'], handleSessionRequest);

  logger.info(
    `Connecting to Http Stream transport on port: ${port}${stateless ? ' (stateless mode)' : ''}`
  );
  app.listen(port);
};
