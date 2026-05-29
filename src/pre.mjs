// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// harden-runner-block-action: pre-step entrypoint.
//
// Runs in the 'pre' lifecycle phase of the GitHub Actions job, BEFORE
// any main step (including any sibling step-security/harden-runner
// pre hook). The script:
//
//   1. Resolves the allow-list source (path > url > default URL).
//   2. Reads or fetches the allow-list content.
//   3. Sanitises it against a strict token allow-list.
//   4. Publishes it as the configured env var (default
//      CONNECTION_ALLOW_LIST) so that any later action's pre hook
//      can read it.
//   5. Publishes step outputs and a step-summary line.
//
// The script has no npm dependencies: it talks to the GitHub Actions
// runner through the documented file/env-var protocol (GITHUB_ENV,
// GITHUB_OUTPUT, GITHUB_STEP_SUMMARY, ::error:: and ::notice::
// workflow commands). Plain Node.js, no bundling, no node_modules to
// vendor.

import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import * as https from 'node:https';
import { URL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';

// Hard limit on how many bytes the HTTPS fetcher will buffer in
// memory from a remote response. The canonical allow-list at
// lfreleng-actions/.github is currently <1 KB and we expect any
// org's file to be well under this ceiling; the limit exists to
// stop a misconfigured or hostile URL from OOM'ing the runner.
const MAX_RESPONSE_BYTES = 1_048_576; // 1 MiB

// ---------------------------------------------------------------------
// Workflow-command helpers
// ---------------------------------------------------------------------

function escapeWorkflowCommand(s) {
  // GitHub Actions workflow commands (lines starting with '::') decode
  // %25 -> %, %0A -> newline, %0D -> carriage return. A raw newline
  // in a workflow-command argument would let a hostile input inject
  // additional commands. Escape the three characters that need it,
  // in the order GitHub itself documents.
  return String(s)
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A');
}

function redactUrl(u) {
  // Strip credentials (userinfo) and query/fragment before logging or
  // publishing as a step output. Keeps scheme + host + path so the
  // resulting string is still useful for debugging without leaking
  // secrets a caller may have included in `url`.
  if (!u) return '';
  try {
    const parsed = new URL(u);
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return '<unparsable URL>';
  }
}

function err(msg) {
  // Emit a GitHub Actions error annotation AND echo to stderr so the
  // raw step log carries the same string even when annotations are
  // suppressed. Escape the annotation payload so user-controlled
  // values cannot inject additional workflow commands.
  console.log(`::error::${escapeWorkflowCommand(msg)}`);
  console.error(msg);
}

function info(msg) {
  console.log(msg);
}

function fail(msg) {
  err(msg);
  process.exit(1);
}

function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) {
    fail("GITHUB_OUTPUT not set; cannot publish step outputs ❌");
  }
  if (/[\r\n]/.test(name)) {
    fail(`Refusing to publish output with newline in name: ${JSON.stringify(name)} ❌`);
  }
  if (/[\r\n]/.test(value)) {
    // Use the documented heredoc form for multi-line values. We do not
    // expect this path for our sanitised single-line allow-list, but
    // keep the helper general.
    const delim = `EOF_${crypto.randomBytes(8).toString('hex')}`;
    fs.appendFileSync(file, `${name}<<${delim}\n${value}\n${delim}\n`);
  } else {
    fs.appendFileSync(file, `${name}=${value}\n`);
  }
}

function exportEnv(name, value) {
  // Mirrors @actions/core.exportVariable: writes to GITHUB_ENV in the
  // delimited-or-plain form GitHub Actions accepts, AND updates the
  // current process env so the rest of this pre script sees the value.
  const file = process.env.GITHUB_ENV;
  if (!file) {
    fail("GITHUB_ENV not set; cannot publish environment variable ❌");
  }
  if (/[\r\n]/.test(value)) {
    const delim = `EOF_${crypto.randomBytes(8).toString('hex')}`;
    fs.appendFileSync(file, `${name}<<${delim}\n${value}\n${delim}\n`);
  } else {
    fs.appendFileSync(file, `${name}=${value}\n`);
  }
  process.env[name] = value;
}

function stepSummary(markdown) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (!file) return; // step summary is optional, do not fail without it
  fs.appendFileSync(file, markdown);
}

// ---------------------------------------------------------------------
// Input handling
// ---------------------------------------------------------------------

// GitHub Actions passes inputs to JS actions as INPUT_<NAME>, with
// hyphens converted to underscores and uppercased.
function getInput(name, defaultValue = "") {
  const key = `INPUT_${name.toUpperCase().replace(/-/g, '_')}`;
  const value = process.env[key];
  return value === undefined ? defaultValue : value;
}

const inputPath = getInput('allow_list_path');
const inputUrl = getInput('url');
const inputOrg = getInput('org');
const inputConfig = getInput('config');
const inputToken = getInput('token');
const inputAllowListSummary = getInput('allow_list_summary', 'true');
const envVarName = getInput('env_var_name', 'CONNECTION_ALLOW_LIST');

// 'config' is mutually exclusive with the legacy source inputs.
if (inputConfig !== '') {
  if (inputPath !== '' || inputUrl !== '' || inputOrg !== '') {
    fail(
      "Input 'config' is mutually exclusive with 'allow_list_path', " +
      "'url' and 'org'; specify only one mechanism ❌",
    );
  }
  if (/[\r\n]/.test(inputConfig)) {
    fail("Input 'config' must not contain newline characters ❌");
  }
}

// Reject newlines in allow_list_path/url inputs. Newlines would let
// a caller inject additional outputs/env entries via $GITHUB_ENV /
// $GITHUB_OUTPUT writes.
for (const [name, value] of [
  ['allow_list_path', inputPath],
  ['url', inputUrl],
]) {
  if (/[\r\n]/.test(value)) {
    fail(`Input '${name}' must not contain newline characters ❌`);
  }
}

// Validate env_var_name. Uppercase letters, digits, underscores; must
// not start with a digit. Matches the comment in action.yaml.
if (!/^[A-Z_][A-Z0-9_]*$/.test(envVarName)) {
  fail(`Invalid env_var_name '${envVarName}' (must match ^[A-Z_][A-Z0-9_]*$) ❌`);
}

const repoOwner = process.env.GITHUB_REPOSITORY_OWNER || '';

// ---------------------------------------------------------------------
// Source resolution: path > url > default URL
// ---------------------------------------------------------------------

let source;          // 'path' | 'url' | 'default-url'
let resolvedUrl = '';
let displayUrl = ''; // resolvedUrl with credentials/query/fragment stripped
let inputFilePath = ''; // only set when source === 'path'

if (inputConfig !== '') {
  // Config mode is handled entirely in the async IIFE below via the
  // shared Python resolver; skip the legacy source resolution.
  source = 'config';
} else if (inputPath !== '') {
  source = 'path';
  inputFilePath = inputPath;
  info(`Source: local allow_list_path -> ${inputPath} ✅`);
} else {
  if (inputUrl !== '') {
    resolvedUrl = inputUrl;
    source = 'url';
  } else {
    const org = inputOrg !== '' ? inputOrg : repoOwner;
    // GitHub usernames/org names are 1–39 characters, alphanumerics
    // and hyphens, must not start or end with a hyphen, and must not
    // contain consecutive hyphens. We enforce all four constraints
    // here so a misconfigured value cannot produce a default URL
    // that can never resolve.
    const orgRe = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
    if (!orgRe.test(org)) {
      fail(`Resolved org name is invalid: '${org}' ❌`);
    }
    resolvedUrl = `https://raw.githubusercontent.com/${org}/.github/HEAD/.github/harden-runner/${org}/allow_list.txt`;
    source = 'default-url';
  }
  displayUrl = redactUrl(resolvedUrl);
  info(`Source: ${source} -> ${displayUrl} ✅`);
}

// ---------------------------------------------------------------------
// Fetch / read content
// ---------------------------------------------------------------------

function httpsGet(urlString, redirectsLeft = 5) {
  // The full URL (with any credentials) is passed to https.request;
  // we redact only when surfacing error messages back to logs so we
  // do not leak userinfo / query parameters.
  const safe = redactUrl(urlString);
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(urlString);
    } catch (e) {
      return reject(new Error(`Invalid URL: ${safe}`));
    }
    if (parsed.protocol !== 'https:') {
      return reject(new Error(`Refusing non-https URL: ${safe}`));
    }
    const req = https.request({
      method: 'GET',
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: `${parsed.pathname}${parsed.search}`,
      // Pass through credentials embedded in the URL (parsed.username
      // / parsed.password) so the server sees the auth the caller
      // configured. The userinfo never makes it back into logs or
      // outputs — redactUrl() strips it before any echo.
      auth: parsed.username ? `${parsed.username}:${parsed.password}` : undefined,
      headers: {
        'User-Agent': 'lfreleng-actions/harden-runner-block-action',
        'Accept': 'text/plain, */*;q=0.5',
      },
    }, (res) => {
      const status = res.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(status)) {
        if (redirectsLeft <= 0) {
          // Drain the response stream so the socket can be
          // released back to the agent pool before we reject.
          res.resume();
          return reject(new Error(`Too many redirects fetching ${safe}`));
        }
        const next = res.headers.location;
        if (!next) {
          res.resume();
          return reject(new Error(`Redirect without Location header from ${safe}`));
        }
        const nextUrl = new URL(next, urlString).toString();
        res.resume();
        return resolve(httpsGet(nextUrl, redirectsLeft - 1));
      }
      if (status < 200 || status >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${status} fetching ${safe}`));
      }
      // Pre-check Content-Length when the server advertises one;
      // the runtime byte-counter below catches chunked / lying
      // responses that omit or understate the header.
      const cl = Number.parseInt(res.headers['content-length'] || '', 10);
      if (Number.isFinite(cl) && cl > MAX_RESPONSE_BYTES) {
        res.resume();
        return reject(new Error(
          `Response too large: Content-Length ${cl} exceeds ` +
          `${MAX_RESPONSE_BYTES}-byte limit fetching ${safe}`,
        ));
      }
      const chunks = [];
      let received = 0;
      res.on('data', (c) => {
        received += c.length;
        if (received > MAX_RESPONSE_BYTES) {
          // Abort the in-flight request. req.destroy(err) triggers
          // the req-level 'error' handler (registered below), which
          // is the path that actually rejects the Promise. We do
          // not call reject() directly here because doing so in
          // addition to req.destroy() would either double-reject
          // (no-op after the first) or race the 'error' handler;
          // letting destroy() drive the rejection keeps the flow
          // single-sourced.
          req.destroy(new Error(
            `Response too large: exceeded ${MAX_RESPONSE_BYTES}-byte ` +
            `limit fetching ${safe}`,
          ));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(15000, () => {
      req.destroy(new Error(`Timeout (15s) fetching ${safe}`));
    });
    req.end();
  });
}

async function loadContent() {
  if (source === 'path') {
    // Single stat() call: catches missing file, non-file types, and
    // the size limit in one go. Using statSync alone (rather than
    // existsSync followed by statSync) removes a small TOCTOU
    // window between the two checks.
    let stat;
    try {
      stat = fs.statSync(inputFilePath);
    } catch (e) {
      if (e && e.code === 'ENOENT') {
        fail(`Allow-list file not found at: ${inputFilePath} ❌`);
      }
      fail(`Cannot stat allow-list file '${inputFilePath}': ${e.message} ❌`);
      return ''; // unreachable
    }
    if (!stat.isFile()) {
      fail(`Allow-list path is not a regular file: ${inputFilePath} ❌`);
    }
    if (stat.size > MAX_RESPONSE_BYTES) {
      fail(
        `Allow-list file too large: ${stat.size} bytes exceeds ` +
        `${MAX_RESPONSE_BYTES}-byte limit (${inputFilePath}) ❌`,
      );
    }
    return fs.readFileSync(inputFilePath, 'utf8');
  }
  // URL or default-url
  try {
    return await httpsGet(resolvedUrl);
  } catch (e) {
    // The Error message produced by httpsGet already contains the
    // redacted URL form (see redactUrl()), so e.message is safe to
    // surface.
    fail(`Failed to fetch allow-list from ${displayUrl}: ${e.message} ❌`);
    return ''; // unreachable
  }
}

// ---------------------------------------------------------------------
// Sanitisation
// ---------------------------------------------------------------------

function sanitise(raw) {
  // Strip a leading UTF-8 BOM.
  let text = raw.replace(/^\uFEFF/, '');
  // Strip '#' comments. We strip both full-line comments and inline
  // comments that follow whitespace on a non-comment line (everything
  // from the '#' to end-of-line is removed). The leading whitespace
  // before the '#' is consumed as well.
  text = text.replace(/(^|[ \t])#[^\r\n]*/gm, '$1');
  // Collapse all whitespace (including newlines and tabs) to single
  // spaces, trim.
  text = text.replace(/[\s]+/g, ' ').trim();
  if (text === '') {
    fail("Allow-list is empty after parsing ❌");
  }
  // Validate every token. Each must be one of:
  //   - a bare host with allowed characters [A-Za-z0-9.-];
  //   - a 'subdomain wildcard' that starts with '*.' followed by
  //     a normal host (e.g. '*.githubusercontent.com');
  //   - either of the above with an optional ':<port>' suffix where
  //     port is 1-5 digits AND in the real TCP/UDP range 1-65535.
  //
  // A bare '*' or '*:<port>' would let harden-runner allow ANY
  // host (the entire egress universe) which would defeat the point
  // of block mode; the regex below deliberately rejects those.
  const hostBare = '[A-Za-z0-9][A-Za-z0-9.-]*';
  const hostWild = '\\*\\.[A-Za-z0-9][A-Za-z0-9.-]*';
  const tokenRe = new RegExp(
    `^(?:${hostBare}|${hostWild})(?::[0-9]{1,5})?$`,
  );
  const tokens = text.split(' ');
  for (const token of tokens) {
    if (!tokenRe.test(token)) {
      fail(`Rejected allow-list token '${token}' (must be host[:port] or *.host[:port]) ❌`);
    }
    const colon = token.lastIndexOf(':');
    if (colon !== -1) {
      const port = Number.parseInt(token.slice(colon + 1), 10);
      if (!Number.isFinite(port) || port < 1 || port > 65535) {
        fail(`Rejected allow-list token '${token}' (port out of range 1-65535) ❌`);
      }
    }
  }
  return tokens.join(' ');
}

// ---------------------------------------------------------------------
// Config-mode resolution (shared Python resolver)
// ---------------------------------------------------------------------

function runConfigFlow() {
  // Mask the token before anything else so it cannot leak into logs.
  // Escape the value so a token containing %, CR or LF cannot break
  // the ::add-mask:: command or inject additional workflow commands.
  if (inputToken) {
    console.log(`::add-mask::${escapeWorkflowCommand(inputToken)}`);
  }

  // Preflight: the shared resolver needs python3 on the runner.
  const probe = spawnSync('python3', ['--version'], { encoding: 'utf8' });
  if (probe.status !== 0) {
    fail("python3 is required for the 'config' input but was not found ❌");
  }

  const here = path.dirname(fileURLToPath(import.meta.url));
  const script = path.join(here, 'resolve_config_source.py');

  // An empty --step-summary target suppresses the summary block
  // (e.g. matrix legs other than the first).
  const summaryTarget = inputAllowListSummary === 'false'
    ? ''
    : (process.env.GITHUB_STEP_SUMMARY || '');

  // The token is passed via the environment (CONFIG_TOKEN), never on
  // the command line, so it cannot appear in a process listing. We
  // also strip the runner-provided INPUT_TOKEN from the child
  // environment: the resolver reads (and pops) CONFIG_TOKEN, so
  // leaving INPUT_TOKEN in place would still leak the secret into the
  // git subprocesses the resolver spawns.
  const childEnv = { ...process.env, CONFIG_TOKEN: inputToken };
  delete childEnv.INPUT_TOKEN;
  const res = spawnSync('python3', [
    script,
    '--config', inputConfig,
    '--workflow-org', repoOwner,
    '--family', 'harden-runner',
    '--mode', 'endpoints',
    '--token-env', 'CONFIG_TOKEN',
    '--content-key', 'allowed_endpoints',
    '--summary-title', '🛡️ Harden Runner Allow-list',
    '--summary-unit', 'Endpoints',
    '--github-output', process.env.GITHUB_OUTPUT || '',
    '--step-summary', summaryTarget,
    '--json-stdout',
  ], {
    encoding: 'utf8',
    env: childEnv,
    // The resolver allows allow-list files up to 1 MiB and serialises
    // the token list as JSON on stdout; raise maxBuffer well above
    // Node's 1 MiB default so a near-limit file cannot trigger
    // ENOBUFS before the env var is exported.
    maxBuffer: 16 * 1024 * 1024,
  });

  if (res.stderr) {
    process.stderr.write(res.stderr);
  }
  if (res.status !== 0) {
    fail(`Failed to resolve allow-list from config '${inputConfig}' ❌`);
  }

  let data;
  try {
    data = JSON.parse(res.stdout.trim());
  } catch (e) {
    fail(`Could not parse config resolver output ❌`);
  }

  if (!data.found) {
    // Unlike python-audit-action, an empty allow-list is fatal here:
    // harden-runner block mode with no endpoints breaks all egress.
    fail(`No allow-list found via config '${inputConfig}' ❌`);
  }

  const sanitised = data.tokens.join(' ');
  // The resolver already wrote the step outputs and summary; we only
  // need to publish the env var the downstream harden-runner pre hook
  // consumes.
  exportEnv(envVarName, sanitised);
  info(`Loaded ${data.count} allow-list endpoints via config ✅`);
}

// ---------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------

(async () => {
  if (inputConfig !== '') {
    runConfigFlow();
    return;
  }

  const raw = await loadContent();
  const sanitised = sanitise(raw);

  // Publish the env var first so it is visible to every later
  // action's pre hook (notably step-security/harden-runner).
  exportEnv(envVarName, sanitised);
  setOutput('allowed_endpoints', sanitised);
  setOutput('source', source);
  // Publish the redacted form of the URL for resolved_url so a
  // credential-bearing 'url' input cannot leak userinfo / query
  // parameters into the workflow output stream or the step summary.
  setOutput('resolved_url', displayUrl);

  const count = sanitised.split(' ').filter(Boolean).length;
  info(`Loaded ${count} allow-list endpoints ✅`);
  if (inputAllowListSummary !== 'false') {
    stepSummary(
      [
        "### 🛡️ Harden Runner Allow-list",
        "",
        `- Source: \`${source}\`${displayUrl ? `  (\`${displayUrl}\`)` : ''}`,
        `- Endpoints loaded: **${count}**`,
        `- Published as env var: \`${envVarName}\``,
        "",
      ].join('\n')
    );
  }
})().catch((e) => {
  fail(`Unexpected error in pre step: ${e.stack || e.message || e} ❌`);
});
