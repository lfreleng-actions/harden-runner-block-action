// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// DNS validation of allow-list hostnames.
//
// step-security/harden-runner's agent resolves every non-wildcard
// allowed endpoint before it installs its block-mode firewall. If ANY
// of them fails to resolve, the agent reverts its changes and the job
// runs with no egress filtering and no egress monitoring at all, while
// the harden-runner step still reports success. One stale hostname in
// a shared allow-list therefore silently disables block mode for every
// job that consumes it.
//
// This module asks the question the agent will ask, before the agent
// asks it, so the caller can act on the answer (see the
// 'invalid_records' input). It covers the allow-list entries alone:
// the endpoints the agent adds implicitly (GitHub, StepSecurity and
// GitHub Meta API hosts) are outside the caller's control, so there is
// nothing to filter, and mirroring that set would drift with each
// agent release. It mirrors the agent deliberately:
//
//   - The agent queries Google's DNS-over-HTTPS JSON API for an A
//     record, falling back to Cloudflare's only when the Google request
//     fails in transport. It does NOT use the runner's resolver, so
//     neither does this module: the runner's resolver (Azure DNS on
//     GitHub-hosted runners) can disagree with Google.
//   - The agent accepts a name only when the answer carries a type-1
//     (A) record. A name with only AAAA records, or a CNAME whose
//     target has no A record, fails open just as an NXDOMAIN does.
//   - Wildcard entries are never pre-resolved by the agent, so they
//     cannot trigger the failure and are skipped here.
//   - In block mode the agent refuses names under '.internal', which
//     makes them fail open too.
//
// DoH runs over HTTPS, so transport reliability comes from TCP and TLS
// rather than from UDP retransmission; on top of that, every query is
// retried with jittered exponential backoff, the hostnames are resolved
// through a bounded concurrency pool, and an overall deadline caps the
// worst case when a provider is unreachable.
//
// Each hostname gets one of three verdicts:
//
//   valid          an A record was returned
//   invalid        an authoritative negative answer: NXDOMAIN, or
//                  NOERROR with no A record (NODATA). The agent WILL
//                  fail open on this name.
//   indeterminate  no verdict was reached: SERVFAIL/REFUSED, HTTP or
//                  transport errors, or the deadline expired. The agent
//                  MAY fail open on this name.

export const MODES = Object.freeze(['filter', 'warning', 'error', 'ignore']);

// Each provider is identified by its host; the agent queries these two
// in this order.
export const PROVIDERS = Object.freeze([
  { host: 'dns.google', path: '/resolve' },
  { host: 'cloudflare-dns.com', path: '/dns-query' },
]);

// Tuned against the lfreleng-actions allow-list (155 distinct names) on
// cold processes: 16-64 concurrent requests complete in ~250-450 ms;
// 8 took 650-1700 ms. The deadline bounds the case where both providers
// are unreachable, which would otherwise cost
// ceil(hosts / concurrency) * attempts * timeout.
export const DEFAULTS = Object.freeze({
  concurrency: 32,
  attempts: 3,
  attemptTimeoutMs: 3000,
  backoffBaseMs: 200,
  deadlineMs: 15000,
});

const DNS_TYPE_A = 1;
const RCODE_NOERROR = 0;
const RCODE_NXDOMAIN = 3;
const RCODE_NAMES = { 1: 'FORMERR', 2: 'SERVFAIL', 4: 'NOTIMP', 5: 'REFUSED' };

// Extract the hostname from an allow-list token ('host[:port]'),
// normalised for de-duplication and querying. Returns null for the
// wildcard entries the agent never pre-resolves.
export function hostOf(token) {
  if (token.startsWith('*.')) return null;
  return token.replace(/:\d+$/, '').replace(/\.$/, '').toLowerCase();
}

// Classify one DoH JSON response body.
//   { verdict: 'valid' | 'invalid' } is final;
//   { verdict: 'retry' } means try again (server-side failure).
export function classifyResponse(body) {
  const answers = Array.isArray(body?.Answer) ? body.Answer : [];
  if (answers.some((a) => a?.type === DNS_TYPE_A)) {
    return { verdict: 'valid' };
  }
  if (body?.Status === RCODE_NXDOMAIN) {
    return { verdict: 'invalid', detail: 'NXDOMAIN (name does not exist)' };
  }
  if (body?.Status === RCODE_NOERROR) {
    return { verdict: 'invalid', detail: 'no A record (NODATA)' };
  }
  const rcode = RCODE_NAMES[body?.Status] || `rcode ${body?.Status}`;
  return { verdict: 'retry', detail: rcode };
}

const realSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// One request to one provider, classified the way the agent sees it.
// The agent's Go http.Client.Do() errors only when the request itself
// fails in transport, and that is the sole condition under which it
// moves to its fallback provider. A response that arrives but is
// unusable (an HTTP error status, an unreadable or unparsable body)
// ends the agent's lookup with no fallback, so here it is a retry
// against the same provider rather than a reason to switch.
//   { kind: 'transport', detail }  try the next provider
//   { kind: 'unusable', detail }   retry this provider
//   { kind: 'answer', body }       classify the DNS answer
async function queryProvider(provider, host, timeoutMs, fetchImpl) {
  const url = new URL(provider.path, `https://${provider.host}`);
  url.searchParams.set('name', host);
  url.searchParams.set('type', 'A');
  const signal = AbortSignal.timeout(timeoutMs);
  let res;
  try {
    res = await fetchImpl(url, {
      headers: { accept: 'application/dns-json' },
      signal,
    });
  } catch (e) {
    return { kind: 'transport', detail: describeError(e) };
  }
  if (!res.ok) {
    return { kind: 'unusable', detail: `HTTP ${res.status}` };
  }
  try {
    return { kind: 'answer', body: await res.json() };
  } catch (e) {
    return { kind: 'unusable', detail: `unreadable response (${describeError(e)})` };
  }
}

function describeError(e) {
  return e?.name === 'TimeoutError' ? 'timed out' : String(e?.message || e);
}

// Resolve one hostname to a verdict, retrying until a final answer, the
// attempt limit, or the shared deadline.
export async function resolveHost(host, opts = {}) {
  const {
    attempts = DEFAULTS.attempts,
    attemptTimeoutMs = DEFAULTS.attemptTimeoutMs,
    backoffBaseMs = DEFAULTS.backoffBaseMs,
    deadline = Infinity,
    providers = PROVIDERS,
    fetchImpl = globalThis.fetch,
    sleep = realSleep,
    now = Date.now,
    random = Math.random,
  } = opts;

  // The agent refuses these outright in block mode, whatever DNS says.
  if (host === 'internal' || host.endsWith('.internal')) {
    return {
      verdict: 'invalid',
      detail: "harden-runner refuses '.internal' names in block mode",
    };
  }

  let lastDetail = 'deadline expired before the first attempt';
  for (let attempt = 0; attempt < attempts; attempt++) {
    // Each provider is tried in order; the next one only on a transport
    // failure, as the agent falls back.
    for (const provider of providers) {
      const remaining = deadline - now();
      if (remaining <= 0) {
        return { verdict: 'indeterminate', detail: `${lastDetail}; deadline expired` };
      }
      const reply = await queryProvider(
        provider,
        host,
        Math.min(attemptTimeoutMs, remaining),
        fetchImpl,
      );
      if (reply.kind === 'transport') {
        lastDetail = `${provider.host}: ${reply.detail}`;
        continue;
      }
      if (reply.kind === 'answer') {
        const result = classifyResponse(reply.body);
        if (result.verdict !== 'retry') {
          return { ...result, provider: provider.host, attempts: attempt + 1 };
        }
        lastDetail = `${provider.host}: ${result.detail}`;
      } else {
        lastDetail = `${provider.host}: ${reply.detail}`;
      }
      // The provider answered, however unhelpfully, so the agent would
      // not fall back; neither do we. Retry instead.
      break;
    }
    if (attempt + 1 < attempts) {
      // Full jitter keeps 32 concurrent retries from synchronising. The
      // wait never outlasts the deadline: with no time left there is
      // nothing to retry for.
      const remaining = deadline - now();
      if (remaining <= 0) {
        return { verdict: 'indeterminate', detail: `${lastDetail}; deadline expired` };
      }
      const backoff = Math.round(backoffBaseMs * 2 ** attempt * (0.5 + random()));
      await sleep(Math.min(backoff, remaining));
    }
  }
  return { verdict: 'indeterminate', detail: lastDetail };
}

// Run fn over items with at most `limit` in flight, preserving order.
async function pool(items, limit, fn) {
  const results = Array.from({ length: items.length });
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}

// Validate every resolvable hostname in an allow-list.
//
// Returns per-token verdicts so callers can filter or report the
// entries exactly as written in the allow-list, plus the counts and
// timing needed for the summary.
export async function validateAllowList(tokens, opts = {}) {
  const {
    concurrency = DEFAULTS.concurrency,
    deadlineMs = DEFAULTS.deadlineMs,
    now = Date.now,
  } = opts;

  const started = now();
  const deadline = started + deadlineMs;

  const hosts = [];
  const seen = new Set();
  let wildcards = 0;
  for (const token of tokens) {
    const host = hostOf(token);
    if (host === null) {
      wildcards++;
    } else if (!seen.has(host)) {
      seen.add(host);
      hosts.push(host);
    }
  }

  const verdicts = await pool(hosts, concurrency, (host) =>
    resolveHost(host, { ...opts, deadline, now }),
  );
  const byHost = new Map(hosts.map((h, i) => [h, verdicts[i]]));

  const invalid = [];
  const indeterminate = [];
  for (const token of tokens) {
    const host = hostOf(token);
    if (host === null) continue;
    const v = byHost.get(host);
    if (v.verdict === 'invalid') invalid.push({ token, detail: v.detail });
    if (v.verdict === 'indeterminate') indeterminate.push({ token, detail: v.detail });
  }

  const indeterminateHosts = verdicts.filter((v) => v.verdict === 'indeterminate').length;
  return {
    hostsChecked: hosts.length,
    wildcardsSkipped: wildcards,
    invalid,
    indeterminate,
    // When a large share of names reached no verdict, the problem is
    // almost certainly the path to the DoH providers rather than the
    // allow-list. Filtering those names would strip legitimate
    // endpoints wholesale, so callers must not.
    degraded: hosts.length > 0 && indeterminateHosts * 4 > hosts.length,
    elapsedMs: now() - started,
  };
}

// Decide what the job should do with a validation result.
//
// Returns the tokens to publish, the egress policy to publish, and
// whether the step must fail. Pure, so every mode is unit-testable.
export function applyMode(mode, tokens, result) {
  const drop = new Set(result.invalid.map((r) => r.token));
  if (mode === 'filter' && !result.degraded) {
    for (const r of result.indeterminate) drop.add(r.token);
  }

  const hasInvalid = result.invalid.length > 0;
  switch (mode) {
    case 'filter':
      return {
        tokens: tokens.filter((t) => !drop.has(t)),
        egressPolicy: 'block',
        fail: false,
        dropped: [...drop],
      };
    case 'warning':
      return {
        tokens,
        egressPolicy: hasInvalid ? 'audit' : 'block',
        fail: false,
        dropped: [],
      };
    case 'error':
      return { tokens, egressPolicy: 'block', fail: hasInvalid, dropped: [] };
    case 'ignore':
      return { tokens, egressPolicy: 'block', fail: false, dropped: [] };
    default:
      throw new Error(`unknown invalid_records mode '${mode}'`);
  }
}
