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
function normalise(raw) {
  return raw
    .replace(/^\uFEFF/, '')
    .replace(/(^|[ \t])#[^\r\n]*/gm, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

// The regex admits 1-5 digits; narrow that to the real TCP/UDP range.
function checkPort(token) {
  const colon = token.lastIndexOf(':');
  if (colon === -1) return;
  const port = Number.parseInt(token.slice(colon + 1), 10);
  if (!Number.isFinite(port) || port < MIN_PORT || port > MAX_PORT) {
    fail(
      `Rejected allow-list token '${token}' ` +
      `(port out of range ${MIN_PORT}-${MAX_PORT}) ❌`,
    );
  }
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
    if (!TOKEN_RE.test(token)) {
      fail(
        `Rejected allow-list token '${token}' ` +
        '(must be host[:port] or *.host[:port]) ❌',
      );
    }
    checkPort(token);
  }
  return tokens.join(' ');
}
