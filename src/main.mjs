// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// harden-runner-block-action: main-step entrypoint.
//
// All the loading / sanitising / validating / exporting work happens
// in pre.mjs, so the env var is already visible to any sibling
// action's pre hook by the time main runs.
//
// Main has two jobs. First it publishes the step outputs: the runner
// discards outputs written during the pre phase (pre steps carry no
// context name), so pre hands them over in a file under RUNNER_TEMP
// and they are written again here, where 'steps.<id>.outputs' picks
// them up.
//
// Then it waits for harden-runner's agent. Every pre hook has run by
// now, harden-runner's included, and no other main step has, so this
// is the moment to make sure egress enforcement is in place before a
// step opens a connection. harden-runner's own pre hook gives up
// waiting after nine seconds, which a large allow-list exceeds on
// every run; see agent-ready.mjs for the race that follows.

import { fail, info, republishOutputs } from './actions-io.mjs';
import { enforceAgentReadyPolicy } from './agent-ready.mjs';
import { readInputs } from './inputs.mjs';

async function main() {
  const count = republishOutputs();
  info(`Allow-list loader main step: published ${count} output(s) from pre ✅`);

  await enforceAgentReadyPolicy(readInputs());
}

main().catch((e) => {
  fail(`Unexpected error in main step: ${e.stack || e.message || e} ❌`);
});
