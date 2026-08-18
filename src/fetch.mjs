// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Allow-list retrieval: a size-capped HTTPS fetcher and a local file
// reader, both bounded by MAX_RESPONSE_BYTES.

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
const REQUEST_TIMEOUT_MS = 15000;

function requestOptions(parsed) {
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
    },
  };
}

// Resolve the next hop of a redirect, or reject when the response
// cannot be followed. Every exit path drains the response stream so
// the socket returns to the agent pool.
function followRedirect(res, urlString, redirectsLeft, safe, resolve, reject) {
  res.resume();
  if (redirectsLeft <= 0) {
    reject(new Error(`Too many redirects fetching ${safe}`));
    return;
  }
  const next = res.headers.location;
  if (!next) {
    reject(new Error(`Redirect without Location header from ${safe}`));
    return;
  }
  resolve(httpsGet(new URL(next, urlString).toString(), redirectsLeft - 1));
}

// Buffer the response body, aborting as soon as it exceeds the cap.
function collectBody(req, res, safe, resolve, reject) {
  // Pre-check Content-Length when the server advertises one; the
  // runtime byte-counter below catches chunked / lying responses that
  // omit or understate the header.
  const advertised = Number.parseInt(res.headers['content-length'] || '', 10);
  if (Number.isFinite(advertised) && advertised > MAX_RESPONSE_BYTES) {
    res.resume();
    reject(new Error(
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
      // Abort the in-flight request. req.destroy(err) triggers the
      // req-level 'error' handler, which is the path that actually
      // rejects the Promise. We do not call reject() directly here
      // because doing so in addition to req.destroy() would either
      // double-reject (no-op after the first) or race the 'error'
      // handler; letting destroy() drive the rejection keeps the flow
      // single-sourced.
      req.destroy(new Error(
        `Response too large: exceeded ${MAX_RESPONSE_BYTES}-byte ` +
        `limit fetching ${safe}`,
      ));
      return;
    }
    chunks.push(chunk);
  });
  res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  res.on('error', reject);
}

// Fetch `urlString` over HTTPS, following up to `redirectsLeft` hops.
//
// The full URL (with any credentials) reaches https.request; error
// messages carry the redacted form only, so userinfo and query
// parameters never reach the logs.
export function httpsGet(urlString, redirectsLeft = 5) {
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

    const req = https.request(requestOptions(parsed), (res) => {
      const status = res.statusCode || 0;
      if (REDIRECT_STATUSES.includes(status)) {
        followRedirect(res, urlString, redirectsLeft, safe, resolve, reject);
        return;
      }
      if (status < 200 || status >= 300) {
        res.resume();
        reject(new Error(`HTTP ${status} fetching ${safe}`));
        return;
      }
      collectBody(req, res, safe, resolve, reject);
    });

    req.on('error', reject);
    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(
        `Timeout (${REQUEST_TIMEOUT_MS / 1000}s) fetching ${safe}`,
      ));
    });
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
