// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// harden-runner-block-action: pre-step entrypoint.
//
// Runs in the 'pre' lifecycle phase of the GitHub Actions job, BEFORE
// any main step (including any sibling step-security/harden-runner
// pre hook). The script:
//
//   1. Resolves the allow-list source (config, or path > url > default
//      URL).
//   2. Reads or fetches the allow-list content.
//   3. Sanitises it against a strict token allow-list.
//   4. Publishes it as the configured env var (default
//      CONNECTION_ALLOW_LIST) so that any later action's pre hook
//      can read it.
//   5. Publishes step outputs and a step-summary line.
//
// The script has no npm dependencies: it talks to the GitHub Actions
// runner through the documented file/env-var protocol. Plain Node.js,
// no bundling, no node_modules to vendor.

import { exportEnv, fail, info, setOutput, stepSummary } from './actions-io.mjs';
import { readInputs, resolveSource } from './inputs.mjs';
import { httpsGet, readLocalFile } from './fetch.mjs';
import { sanitise } from './sanitise.mjs';
import { runConfigFlow } from './config-flow.mjs';

async function loadContent({ source, filePath, url, displayUrl }) {
  if (source === 'path') {
    return readLocalFile(filePath);
  }
  try {
    return await httpsGet(url);
  } catch (e) {
    // The Error message produced by httpsGet already carries the
    // redacted URL form, so e.message is safe to surface.
    fail(`Failed to fetch allow-list from ${displayUrl}: ${e.message} ❌`);
    return ''; // unreachable
  }
}

function publishSummary({ source, displayUrl, count, envVarName }) {
  stepSummary(
    [
      '### 🛡️ Harden Runner Allow-list',
      '',
      `- Source: \`${source}\`${displayUrl ? `  (\`${displayUrl}\`)` : ''}`,
      `- Endpoints loaded: **${count}**`,
      `- Published as env var: \`${envVarName}\``,
      '',
    ].join('\n'),
  );
}

async function main() {
  const inputs = readInputs();

  if (inputs.config !== '') {
    runConfigFlow(inputs);
    return;
  }

  const resolved = resolveSource(inputs);
  const sanitised = sanitise(await loadContent(resolved));

  // Publish the env var first so it is visible to every later action's
  // pre hook (notably step-security/harden-runner).
  exportEnv(inputs.envVarName, sanitised);
  setOutput('allowed_endpoints', sanitised);
  setOutput('source', resolved.source);
  // resolved_url carries the redacted URL so a credential-bearing 'url'
  // input cannot leak userinfo / query parameters into the workflow
  // output stream or the step summary.
  setOutput('resolved_url', resolved.displayUrl);

  const count = sanitised.split(' ').filter(Boolean).length;
  info(`Loaded ${count} allow-list endpoints ✅`);
  if (inputs.summary) {
    publishSummary({ ...resolved, count, envVarName: inputs.envVarName });
  }
}

main().catch((e) => {
  fail(`Unexpected error in pre step: ${e.stack || e.message || e} ❌`);
});
