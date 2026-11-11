// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Allow-list retrieval: a size-capped, deadline-bounded HTTPS fetcher
// and a local file reader, both bounded by MAX_RESPONSE_BYTES.

import * as fs from 'node:fs';
import * as https from 'node:https';
import { URL } from 'node:url';
import { fail, redactUrl } from './actions-io.mjs';

// Hard limit on how many bytes the HTTPS fetcher will buffer in
// memory from a remote response. The canonical allow-list at
// lfreleng-actions/.github is currently <1 KB and we expect any
// org's file to be well under this ceiling; the limit exists to
// stop a misconfigured or hostile URL from OOM'ing the runner.
export const MAX_RESPONSE_BYTES = 1_048_576; // 1 MiB

const REDIRECT_STATUSES = [301, 302, 303, 307, 308];
// The whole fetch, redirects included, must finish within this. It is
// a deadline rather than an inactivity timeout: a server that trickles
// a byte at a time, or a DNS lookup that never answers, would keep an
// inactivity timer from ever firing.
export const REQUEST_TIMEOUT_MS = 15000;

// Build the request options. `headers` are the caller's extra headers
// for this hop alone.
function requestOptions(parsed, headers) {
  return {
    method: 'GET',
    hostname: parsed.hostname,
    port: parsed.port || 443,
    path: `${parsed.pathname}${parsed.search}`,
    // Pass through credentials embedded in the URL (parsed.username /
    // parsed.password) so the server sees the auth the caller
    // configured. The userinfo never makes it back into logs or
    // outputs — redactUrl() strips it before any echo.
    auth: parsed.username ? `${parsed.username}:${parsed.password}` : undefined,
    headers: {
      'User-Agent': 'lfreleng-actions/harden-runner-block-action',
      Accept: 'text/plain, */*;q=0.5',
      ...headers,
    },
  };
}

function timeoutError(safe) {
  return new Error(`Timeout (deadline reached) fetching ${safe}`);
}

// The next hop of a redirect as { url }, or { error } when the
// response cannot be followed. A Location that is not a URL is an
// error like any other, rather than an exception thrown out of the
// response callback where nothing would catch it.
function redirectTarget(res, urlString, redirectsLeft, safe) {
  if (redirectsLeft <= 0) {
    return { error: new Error(`Too many redirects fetching ${safe}`) };
  }
  const location = res.headers.location;
  if (!location) {
    return { error: new Error(`Redirect without Location header from ${safe}`) };
  }
  try {
    return { url: new URL(location, urlString).toString() };
  } catch {
    return { error: new Error(`Redirect with an invalid Location header from ${safe}`) };
  }
}

// Buffer the response body, settling through `finish` as soon as it
// ends or exceeds the cap.
function collectBody(res, safe, finish) {
  // Pre-check Content-Length when the server advertises one; the
  // runtime byte-counter below catches chunked / lying responses that
  // omit or understate the header.
  const advertised = Number.parseInt(res.headers['content-length'] || '', 10);
  if (Number.isFinite(advertised) && advertised > MAX_RESPONSE_BYTES) {
    finish(new Error(
      `Response too large: Content-Length ${advertised} exceeds ` +
      `${MAX_RESPONSE_BYTES}-byte limit fetching ${safe}`,
    ));
    return;
  }

  const chunks = [];
  let received = 0;
  res.on('data', (chunk) => {
    received += chunk.length;
    if (received > MAX_RESPONSE_BYTES) {
      finish(new Error(
        `Response too large: exceeded ${MAX_RESPONSE_BYTES}-byte ` +
        `limit fetching ${safe}`,
      ));
      return;
    }
    chunks.push(chunk);
  });
  res.on('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
}

// Fetch `urlString` over HTTPS, following up to `redirectsLeft` hops,
// all of them within one absolute `deadline` (epoch milliseconds).
// `headers` go with the first request only: a redirect may leave the
// host they were meant for, and an Authorization header must not
// follow it there. `request` is https.request unless a test
// substitutes it.
//
// Every exit settles the promise once, stops the deadline timer and
// destroys the request. A response this function will not consume (a
// redirect, an error status, an oversized body) is therefore cut off
// rather than drained: draining would download whatever the server
// cares to send, and keep the process alive while it does.
//
// The full URL (with any credentials) reaches the request; error
// messages carry the redacted form only, so userinfo and query
// parameters never reach the logs.
export function httpsGet(urlString, options = {}) {
  const {
    headers = {},
    redirectsLeft = 5,
    deadline = Date.now() + REQUEST_TIMEOUT_MS,
    request = https.request,
  } = options;
  const safe = redactUrl(urlString);
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(urlString);
    } catch {
      reject(new Error(`Invalid URL: ${safe}`));
      return;
    }
    if (parsed.protocol !== 'https:') {
      reject(new Error(`Refusing non-https URL: ${safe}`));
      return;
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      reject(timeoutError(safe));
      return;
    }

    let settled = false;
    let timer;
    let req;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.destroy();
      if (error) reject(error);
      else resolve(value);
    };

    req = request(requestOptions(parsed, headers), (res) => {
      // Destroying the request can error the response; that is this
      // function's own doing once it has settled, and finish() ignores
      // it, but the listener must exist or the error is unhandled.
      res.on('error', (e) => finish(e));
      const status = res.statusCode || 0;
      if (REDIRECT_STATUSES.includes(status)) {
        const next = redirectTarget(res, urlString, redirectsLeft, safe);
        if (next.error) {
          finish(next.error);
          return;
        }
        finish(null, httpsGet(next.url, { redirectsLeft: redirectsLeft - 1, deadline, request }));
        return;
      }
      if (status < 200 || status >= 300) {
        // The status travels with the error so a caller can tell an
        // absent file (404) from a failure to read one.
        const error = new Error(`HTTP ${status} fetching ${safe}`);
        error.status = status;
        finish(error);
        return;
      }
      collectBody(res, safe, finish);
    });

    req.on('error', (e) => finish(e));
    timer = setTimeout(() => finish(timeoutError(safe)), remaining);
    req.end();
  });
}

// Read a local allow-list, rejecting anything that is not a regular
// file within the size cap.
//
// A single stat() call catches missing files, non-file types and the
// size limit in one go. Using statSync alone (rather than existsSync
// followed by statSync) removes a small TOCTOU window.
export function readLocalFile(filePath) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (e) {
    if (e && e.code === 'ENOENT') {
      fail(`Allow-list file not found at: ${filePath} ❌`);
    }
    fail(`Cannot stat allow-list file '${filePath}': ${e.message} ❌`);
    return ''; // unreachable
  }
  if (!stat.isFile()) {
    fail(`Allow-list path is not a regular file: ${filePath} ❌`);
  }
  if (stat.size > MAX_RESPONSE_BYTES) {
    fail(
      `Allow-list file too large: ${stat.size} bytes exceeds ` +
      `${MAX_RESPONSE_BYTES}-byte limit (${filePath}) ❌`,
    );
  }
  return fs.readFileSync(filePath, 'utf8');
}
