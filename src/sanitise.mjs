// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Allow-list sanitisation: strict validation of the tokens harden-runner
// will be asked to permit.

import { fail } from './actions-io.mjs';

// Each token must be one of:
//   - a bare host with allowed characters [A-Za-z0-9.-];
//   - a 'subdomain wildcard' that starts with '*.' followed by a normal
//     host (e.g. '*.githubusercontent.com');
//   - either of the above with an optional ':<port>' suffix.
//
// A bare '*' or '*:<port>' would let harden-runner allow ANY host (the
// entire egress universe), defeating the point of block mode; the
// pattern below deliberately rejects those.
const HOST_BARE = '[A-Za-z0-9][A-Za-z0-9.-]*';
const HOST_WILD = '\\*\\.[A-Za-z0-9][A-Za-z0-9.-]*';
const TOKEN_RE = new RegExp(
  `^(?:${HOST_BARE}|${HOST_WILD})(?::[0-9]{1,5})?$`,
);

const MIN_PORT = 1;
const MAX_PORT = 65535;

// Drop the BOM, strip '#' comments (full-line and inline, taking the
// preceding whitespace with them), then collapse all remaining
// whitespace to single spaces.
export function normalise(raw) {
  return raw
    .replace(/^\uFEFF/, '')
    .replace(/(^|[ \t])#[^\r\n]*/gm, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

// The regex admits 1-5 digits; narrow that to the real TCP/UDP range.
function portInRange(token) {
  const colon = token.lastIndexOf(':');
  if (colon === -1) return true;
  const port = Number.parseInt(token.slice(colon + 1), 10);
  return Number.isFinite(port) && port >= MIN_PORT && port <= MAX_PORT;
}

// Why a single token is not a valid allow-list entry, or null when it
// is. Callers phrase the refusal; the grammar lives here alone.
export function tokenProblem(token) {
  if (!TOKEN_RE.test(token)) {
    return 'must be host[:port] or *.host[:port]';
  }
  if (!portInRange(token)) {
    return `port out of range ${MIN_PORT}-${MAX_PORT}`;
  }
  return null;
}

// Parse and validate raw allow-list text, returning a single
// space-separated line. Any token that fails validation fails the step:
// silently dropping one would narrow egress in a way the caller never
// asked for and would not see.
export function sanitise(raw) {
  const text = normalise(raw);
  if (text === '') {
    fail('Allow-list is empty after parsing ❌');
  }
  const tokens = text.split(' ');
  for (const token of tokens) {
    const problem = tokenProblem(token);
    if (problem) {
      fail(`Rejected allow-list token '${token}' (${problem}) ❌`);
    }
  }
  return tokens.join(' ');
}
