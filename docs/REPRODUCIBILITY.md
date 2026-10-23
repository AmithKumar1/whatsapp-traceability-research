# Reproducibility Protocol

## Goal

A result is useful only if another researcher can reproduce it without relying on undocumented access to a maintainer's machine, service account, private data, or unpinned dependency tree.

## Required run record

For each paper reproduction or benchmark run, save:

- paper URL, version, access date, and relevant definition/algorithm sections;
- source repository URL, commit hash, license, and any local patch set;
- language compiler/runtime version, dependency lockfile, OS, CPU architecture, memory, and relevant acceleration settings;
- complete public configuration, random seed, dataset generator version, and input sizes;
- commands, stdout/stderr, exit code, raw timing/size measurements, and repeated-run count;
- expected result from the paper, observed result, tolerance policy, and explanation for deviations;
- test result and reviewer approval;
- a manifest of raw outputs and result scripts.

Do not commit real message contents, private case data, signing secrets, access tokens, or confidential provider logs. For sensitive experiments, publish a synthetic generator and sanitized results instead of raw data.

## Benchmark method

- Pin dependency versions for published results. A separate scheduled job can test the current dependency set.
- Use fixed seeds for comparable runs, then use separate random-seed batches for robustness.
- Record warm-up and measurement methodology; distinguish setup/key-generation time from per-message steady-state cost.
- Report median, p90/p95, variance/dispersion, failures, and outliers; retain raw observations.
- Separate path depth from tree width and total number of participants.
- Report signature/proof size and stored metadata in bytes, not only time.
- Test cold-cache and warm-cache paths when relevant.
- State whether measurements include network round trips, quorum communication, trusted timestamp services, and transparency proofs.

## Release reproducibility

Tag public releases, attach source archive checksums, publish a signed release manifest, retain CI logs, and state known non-reproducible elements. For research claims, independent reproduction should not depend on the original implementer's signing keys or hosted infrastructure.
