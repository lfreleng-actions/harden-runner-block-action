// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Input parsing, validation and allow-list source resolution.

import { fail, getInput, info, redactUrl } from './actions-io.mjs';

// GitHub usernames/org names are 1–39 characters, alphanumerics and
// hyphens, must not start or end with a hyphen, and must not contain
// consecutive hyphens. Enforcing all four constraints here stops a
// misconfigured value producing a default URL that can never resolve.
const ORG_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

const ENV_VAR_NAME_RE = /^[A-Z_][A-Z0-9_]*$/;

function rejectNewlines(name, value) {
  if (/[\r\n]/.test(value)) {
    fail(`Input '${name}' must not contain newline characters ❌`);
  }
}

// Newlines in these inputs would let a caller inject additional
// outputs/env entries via the $GITHUB_ENV / $GITHUB_OUTPUT writes.
function validate(inputs) {
  // 'config' is mutually exclusive with the legacy source inputs.
  if (inputs.config !== '') {
    if (inputs.path !== '' || inputs.url !== '' || inputs.org !== '') {
      fail(
        "Input 'config' is mutually exclusive with 'allow_list_path', " +
        "'url' and 'org'; specify only one mechanism ❌",
      );
    }
    rejectNewlines('config', inputs.config);
  }
  rejectNewlines('allow_list_path', inputs.path);
  rejectNewlines('url', inputs.url);

  if (!ENV_VAR_NAME_RE.test(inputs.envVarName)) {
    fail(
      `Invalid env_var_name '${inputs.envVarName}' ` +
      `(must match ${ENV_VAR_NAME_RE.source}) ❌`,
    );
  }
}

export function readInputs() {
  const inputs = {
    path: getInput('allow_list_path'),
    url: getInput('url'),
    org: getInput('org'),
    config: getInput('config'),
    token: getInput('token'),
    summary: getInput('allow_list_summary', 'true') !== 'false',
    envVarName: getInput('env_var_name', 'CONNECTION_ALLOW_LIST'),
    workflowOrg: process.env.GITHUB_REPOSITORY_OWNER || '',
  };
  validate(inputs);
  return inputs;
}

function defaultUrlFor(org) {
  if (!ORG_RE.test(org)) {
    fail(`Resolved org name is invalid: '${org}' ❌`);
  }
  return `https://raw.githubusercontent.com/${org}/.github/HEAD/` +
    `.github/harden-runner/${org}/allow_list.txt`;
}

// Decide where the allow-list comes from: config > path > url > the
// org's default URL. Returns the source label plus whichever of the
// file path / URL that label implies. `displayUrl` is the redacted form
// safe to echo into logs, outputs and the step summary.
export function resolveSource(inputs) {
  if (inputs.config !== '') {
    return { source: 'config', filePath: '', url: '', displayUrl: '' };
  }

  if (inputs.path !== '') {
    info(`Source: local allow_list_path -> ${inputs.path} ✅`);
    return { source: 'path', filePath: inputs.path, url: '', displayUrl: '' };
  }

  const source = inputs.url !== '' ? 'url' : 'default-url';
  const url = inputs.url !== ''
    ? inputs.url
    : defaultUrlFor(inputs.org !== '' ? inputs.org : inputs.workflowOrg);
  const displayUrl = redactUrl(url);
  info(`Source: ${source} -> ${displayUrl} ✅`);
  return { source, filePath: '', url, displayUrl };
}
