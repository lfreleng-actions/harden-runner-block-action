// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// harden-runner-block-action: main-step entrypoint.
//
// All the loading / sanitising / validating / exporting work happens
// in pre.mjs, so the env var is already visible to any sibling
// action's pre hook by the time main runs.
//
// Main's one job is to publish the step outputs. The runner discards
// outputs written during the pre phase (pre steps carry no context
// name), so pre hands them over in a file under RUNNER_TEMP and they
// are written again here, where 'steps.<id>.outputs' picks them up.

import { info, republishOutputs } from './actions-io.mjs';

const count = republishOutputs();
info(`Allow-list loader main step: published ${count} output(s) from pre ✅`);
