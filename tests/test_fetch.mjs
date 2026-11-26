// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Unit tests for the HTTPS fetcher.
//
// A local plain-HTTP server stands in for the remote host, and the
// fetcher's injectable `request` is http.request, so every path runs
// over a real socket: slow and endless bodies, error statuses that keep
// streaming, redirects good and bad, and a DNS lookup that never
// answers. The server records when each connection closes, which is
// how the tests see that the fetcher cut off what it did not consume.
//
// Run with: node --test tests/test_fetch.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import { MAX_RESPONSE_BYTES, httpsGet } from '../src/fetch.mjs';

const request = (opts, cb) => http.request(opts, cb);

// Serve `handler` on an ephemeral port for the duration of `fn`, which
// receives the base URL (https://, as the fetcher insists) and a list
// that gains one entry each time a client connection closes.
async function withServer(handler, fn) {
  const closed = [];
  const timers = new Set();
  const server = http.createServer((req, res) => handler(req, res, timers));
  server.on('connection', (socket) => socket.on('close', () => closed.push(Date.now())));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `https://127.0.0.1:${server.address().port}`;
  try {
    return await fn(base, closed);
  } finally {
    for (const t of timers) clearInterval(t);
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

// Send a byte every `ms` until the client goes away.
function trickle(res, timers, ms = 20) {
  const t = setInterval(() => res.write('x'), ms);
  timers.add(t);
  res.on('close', () => clearInterval(t));
}

const waitFor = async (predicate, ms = 2000) => {
  const until = Date.now() + ms;
  while (!predicate()) {
    if (Date.now() > until) return false;
    await new Promise((r) => setTimeout(r, 10));
  }
  return true;
};

test('returns the body of a successful response', async () => {
  await withServer((req, res) => res.end('a.example:443\n'), async (base) => {
    assert.equal(await httpsGet(`${base}/list`, { request }), 'a.example:443\n');
  });
});

test('refuses non-https and unparsable URLs without a request', async () => {
  await assert.rejects(httpsGet('http://example.com/x', { request }), /Refusing non-https URL/);
  await assert.rejects(httpsGet('not a url', { request }), /Invalid URL/);
});

test('an error status rejects at once and cuts off a body that keeps streaming', async () => {
  await withServer((req, res, timers) => {
    res.writeHead(404);
    trickle(res, timers);
  }, async (base, closed) => {
    const started = Date.now();
    await assert.rejects(httpsGet(`${base}/missing`, { request }), /HTTP 404 fetching/);
    assert.ok(Date.now() - started < 1000);
    assert.ok(await waitFor(() => closed.length === 1), 'the connection is closed, not drained');
  });
});

test('the deadline bounds a body that trickles forever', async () => {
  await withServer((req, res, timers) => {
    res.writeHead(200);
    trickle(res, timers);
  }, async (base, closed) => {
    const started = Date.now();
    await assert.rejects(
      httpsGet(`${base}/slow`, { request, deadline: Date.now() + 300 }),
      /Timeout \(deadline reached\) fetching/,
    );
    const took = Date.now() - started;
    assert.ok(took >= 250 && took < 1500, `took ${took} ms`);
    assert.ok(await waitFor(() => closed.length === 1));
  });
});

test('the deadline bounds a DNS lookup that never answers', async () => {
  const stalled = (opts, cb) => http.request({ ...opts, lookup: () => {} }, cb);
  const started = Date.now();
  await assert.rejects(
    httpsGet('https://never.example/x', { request: stalled, deadline: Date.now() + 200 }),
    /Timeout \(deadline reached\)/,
  );
  assert.ok(Date.now() - started < 1500);
});

test('an already-passed deadline rejects without a request', async () => {
  let calls = 0;
  const counting = (opts, cb) => { calls++; return http.request(opts, cb); };
  await assert.rejects(httpsGet('https://x.example/', { request: counting, deadline: Date.now() - 1 }), /Timeout/);
  assert.equal(calls, 0);
});

test('follows a relative redirect', async () => {
  await withServer((req, res) => {
    if (req.url === '/old') {
      res.writeHead(302, { Location: '/new' });
      res.end();
    } else {
      res.end(`served ${req.url}`);
    }
  }, async (base) => {
    assert.equal(await httpsGet(`${base}/old`, { request }), 'served /new');
  });
});

test('one deadline covers every redirect hop', async () => {
  let hops = 0;
  await withServer((req, res) => {
    hops++;
    // Each hop takes 120 ms; five of them cannot fit in 300.
    setTimeout(() => {
      res.writeHead(302, { Location: `/hop${hops}` });
      res.end();
    }, 120);
  }, async (base) => {
    await assert.rejects(
      httpsGet(`${base}/hop0`, { request, deadline: Date.now() + 300 }),
      /Timeout \(deadline reached\)/,
    );
    assert.ok(hops <= 3, `${hops} hops ran`);
  });
});

test('a redirect with an unparsable Location rejects instead of throwing', async () => {
  await withServer((req, res) => {
    res.writeHead(302, { Location: 'https://[invalid-host' });
    res.end();
  }, async (base) => {
    await assert.rejects(httpsGet(`${base}/bad`, { request }), /Redirect with an invalid Location header/);
  });
});

test('a redirect without Location, and too many redirects, reject', async () => {
  await withServer((req, res) => {
    if (req.url === '/none') {
      res.writeHead(301);
      res.end();
      return;
    }
    res.writeHead(302, { Location: '/loop' });
    res.end();
  }, async (base) => {
    await assert.rejects(httpsGet(`${base}/none`, { request }), /Redirect without Location header/);
    await assert.rejects(httpsGet(`${base}/loop`, { request, redirectsLeft: 2 }), /Too many redirects/);
  });
});

test('an error status carries the status code', async () => {
  await withServer((req, res) => {
    res.writeHead(req.url === '/gone' ? 404 : 503);
    res.end();
  }, async (base) => {
    await assert.rejects(httpsGet(`${base}/gone`, { request }), (e) => e.status === 404);
    await assert.rejects(httpsGet(`${base}/down`, { request }), (e) => e.status === 503);
  });
});

test('caller headers go with the first hop and never follow a redirect', async () => {
  const seen = [];
  await withServer((req, res) => {
    seen.push([req.url, req.headers.authorization]);
    if (req.url === '/start') {
      res.writeHead(302, { Location: '/next' });
      res.end();
    } else {
      res.end('ok');
    }
  }, async (base) => {
    const body = await httpsGet(`${base}/start`, { request, headers: { Authorization: 'Bearer t0ken' } });
    assert.equal(body, 'ok');
  });
  assert.deepEqual(seen, [['/start', 'Bearer t0ken'], ['/next', undefined]]);
});

test('an advertised oversize body is refused and cut off', async () => {
  await withServer((req, res, timers) => {
    res.writeHead(200, { 'Content-Length': String(MAX_RESPONSE_BYTES + 1) });
    trickle(res, timers);
  }, async (base, closed) => {
    await assert.rejects(httpsGet(`${base}/big`, { request }), /Content-Length .* exceeds/);
    assert.ok(await waitFor(() => closed.length === 1));
  });
});

test('a body that grows past the cap is refused and cut off', async () => {
  const chunk = Buffer.alloc(64 * 1024, 'x');
  await withServer((req, res) => {
    res.writeHead(200);
    const pump = () => {
      while (!res.destroyed && res.write(chunk)) { /* fill the buffer */ }
      if (!res.destroyed) res.once('drain', pump);
    };
    pump();
  }, async (base, closed) => {
    await assert.rejects(httpsGet(`${base}/endless`, { request }), /exceeded .*-byte limit/);
    assert.ok(await waitFor(() => closed.length === 1));
  });
});
