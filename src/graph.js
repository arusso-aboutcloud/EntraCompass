// Microsoft Graph client for EntraCompass.
//
// Read-only. Every collection call follows @odata.nextLink, and every request
// retries on throttling (429) and transient errors (503/504), honouring the
// Retry-After header Graph sends back. This is what lets the scan cover the
// whole tenant instead of a sample.

const V1 = 'https://graph.microsoft.com/v1.0';
const BETA = 'https://graph.microsoft.com/beta';
const MAX_ATTEMPTS = 6;
const MAX_PAGES = 1000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class GraphClient {
  constructor(msalInstance, scopes) {
    this.msal = msalInstance;
    this.scopes = scopes;
  }

  async getToken() {
    const account = this.msal.getActiveAccount() || this.msal.getAllAccounts()[0];
    if (!account) throw new Error('No active account. Please sign in again.');
    try {
      const resp = await this.msal.acquireTokenSilent({ scopes: this.scopes, account });
      return resp.accessToken;
    } catch (err) {
      console.warn('Silent token acquisition failed, redirecting:', err);
      await this.msal.acquireTokenRedirect({ scopes: this.scopes, account });
      throw new Error('Re-authentication required.');
    }
  }

  // Low-level request with throttling-aware retry.
  async request(url, { method = 'GET', body, headers = {} } = {}) {
    let attempt = 0;
    for (;;) {
      attempt++;
      const token = await this.getToken();
      let resp;
      try {
        resp = await fetch(url, {
          method,
          headers: {
            Authorization: 'Bearer ' + token,
            'Content-Type': 'application/json',
            ...headers,
          },
          body: body ? JSON.stringify(body) : undefined,
        });
      } catch (networkErr) {
        if (attempt >= MAX_ATTEMPTS) {
          const err = new Error('Network error calling Microsoft Graph');
          err.httpStatus = 0;
          throw err;
        }
        await sleep(backoff(attempt));
        continue;
      }

      if (resp.ok) {
        if (resp.status === 204) return null;
        const type = resp.headers.get('Content-Type') || '';
        return type.includes('application/json') ? resp.json() : resp.text();
      }

      const retryable = resp.status === 429 || resp.status === 503 || resp.status === 504;
      if (retryable && attempt < MAX_ATTEMPTS) {
        const ra = Number(resp.headers.get('Retry-After'));
        await sleep(Number.isFinite(ra) && ra > 0 ? Math.min(ra, 60) * 1000 : backoff(attempt));
        continue;
      }

      const text = await resp.text().catch(() => '');
      const err = new Error(`Graph API error ${resp.status}`);
      err.httpStatus = resp.status;
      err.detail = text.slice(0, 300);
      throw err;
    }
  }

  get(path, { beta = false, headers } = {}) {
    return this.request((beta ? BETA : V1) + path, { headers });
  }

  post(path, body, { beta = false } = {}) {
    return this.request((beta ? BETA : V1) + path, { method: 'POST', body });
  }

  // Fetches every page of a collection.
  async getAll(path, { beta = false, headers, onPage } = {}) {
    const out = [];
    let next = (beta ? BETA : V1) + path;
    let pages = 0;
    while (next && pages < MAX_PAGES) {
      pages++;
      const data = await this.request(next, { headers });
      if (Array.isArray(data?.value)) out.push(...data.value);
      if (onPage) onPage(out.length);
      next = data?.['@odata.nextLink'] || null;
    }
    return out;
  }
}

function backoff(attempt) {
  return Math.min(30000, 1000 * 2 ** (attempt - 1)) + Math.floor(Math.random() * 400);
}

// Runs `fn` over `items` with at most `limit` in flight at once.
export async function pool(items, limit, fn) {
  const results = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return results;
}

export function reasonFor(err) {
  const s = err?.httpStatus;
  if (s === 401 || s === 403) return 'permission_denied';
  if (s === 400 || s === 404) return 'not_available';
  if (s === 429) return 'throttled';
  if (s >= 500) return 'service_error';
  return 'network_error';
}
