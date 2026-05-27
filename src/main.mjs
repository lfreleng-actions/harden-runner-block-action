// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// harden-runner-block-action: main-step entrypoint.
//
// All the loading / sanitising / exporting work happens in pre.mjs;
// by the time main runs the work is done and the env var is already
// visible to any sibling action's pre hook. This entrypoint exists
// only because the GitHub Actions metadata schema requires a 'main'
// for every action.
//
// The main step prints a short confirmation line so users glancing
// at the log can see the loader has done its work. The pre step
// does not create any temp files (HTTPS responses are buffered in
// memory) so there is nothing to clean up here.

console.log("Allow-list loader main step: nothing more to do (pre already ran) ✅");
