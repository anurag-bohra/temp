# 12c. Repository-maintenance skills and other LLM-facing text (verbatim)

Part C of Chapter 12 (see [12-ai-layer-prompts-and-skills.md](12-ai-layer-prompts-and-skills.md)).

These are **contributor-facing** agent skills and guidance documents shipped in the REA repository. They are *not* installed by `rea setup` (only `reverse-engineer-anything` is; see
`src/application/SetupSkill.ts:22-30`, `MANAGED_SKILL_FILES`). They steer coding agents that *develop* REA, and they encode the project's agent-behaviour norms (evidence discipline, no auto-publishing, fail-closed scope).
Everything below is reproduced byte for byte at HEAD `f75b1a4`. Fences use five backticks.

Contents: (1) `rea-tool-design`, (2) `rea-ci-tests-audit` (+ reference + `agents/openai.yaml`), (3) `rea-changelog-update`, (4) `AGENTS.md`, (5) `docs/tool-design.md`, (6) `docs/reverse-engineering-tools.md`.

## 1. Skill rea-tool-design

Source: `.agents/skills/rea-tool-design/SKILL.md:1-20`

`````markdown
---
name: rea-tool-design
description: Design or change REA investigation tools, CLI/MCP contracts, provider capabilities, and Evidence semantics.
---

# REA tool design

Use the [tool-design guide](../../../docs/tool-design.md) for tool boundaries,
contract semantics, provider ownership, and discoverability. Inspect the current
contract and nearest existing tool relevant to the analyst question; source,
documentation, and live catalogs may describe different versions.

For a design request, return the proposed boundary, input/result shape, Evidence
semantics, nearest alternative, and verification approach. Implement when
requested, preserving the user's scope and existing authorization.

For implementation or verification, consult [testing](../../../docs/testing.md)
for the affected consumer and provider lanes, and
[contributing](../../../CONTRIBUTING.md) for generated-file ownership. Read
provider/workflow guides only as the task requires.
`````

## 2a. Skill rea-ci-tests-audit SKILL.md

Source: `.agents/skills/rea-ci-tests-audit/SKILL.md:1-112`

`````markdown
---
name: rea-ci-tests-audit
description: Audit REA CI and test suites for correctness, fixture drift, false passes, and measured performance; use for suite or workflow investigations and efficiency changes, rather than ordinary feature testing or a single test failure.
---

# REA CI and tests audit

Establish which checks still catch real regressions and which costs can be
removed without losing that protection. The outcome may be a verified fix,
an evidence-backed recommendation, or an explicit decision to stop.

Follow the checkout's `AGENTS.md`, [testing guide](../../../docs/testing.md),
and [contribution rules](../../../CONTRIBUTING.md). Use their current commands
and pinned toolchain, rather than commands remembered from an earlier audit.
Preserve the requested scope: investigation alone does not authorize edits;
this skill does not grant permission to publish issues, push, or merge. Existing
user authorization still applies. Keep audit notes and raw results outside the
tracked tree, normally in a task-specific `/tmp` directory.

## Establish the executed baseline

Fetch when the user asks for latest main. Pin the baseline SHA and inspected
workflow revision; use an isolated worktree when changing or comparing code.
Do not modify another task's checkout. Record dirty changes and the exact
command, toolchain, host, selected tests, instrumentation, and prerequisites.
An old run is evidence for its executed revision, even if main advances.

Trace workflow triggers, changed-path selection, job dependencies, reusable
actions, package scripts, test discovery, artifact producers, and report gates
through to the commands that actually execute. Include scripts, generated data,
runtime registration, and subprocess boundaries missing from import graphs.
Check positive and negative selection paths: required files must be discovered
once per intended test configuration; deliberate platform/configuration repeats
are separate coverage. A missing explicit test or missing required report must
not turn green. Optional lanes may skip; preserve their stated prerequisites.

Use existing timing and failure artifacts to select suspicious families. Run
relevant checks to establish a baseline; reserve a full local suite for broad
CI diagnosis or uncertainty that focused checks cannot resolve. Do not rebuild
or rerun an unchanged complete suite after every documentation edit.

## Prove the failure or protection

For each candidate, state the expected observable behavior and its owner,
then construct the smallest reproduction against production behavior. Follow
the producer and affected consumers before deciding where to fix it.

- For drift, compare fixtures with current admission requirements, protocol
  replies, named contracts, tool versions, and actual public entrypoints. A
  plausible-looking mock can fail before the behavior its test claims to cover.
  Search the whole affected fixture family, including other version strings.
  Preserve intentionally malformed fixtures and test their intended rejection.
- For a suspicious green test, perturb the relevant behavior in an isolated
  copy or inject a controlled failure. Verify that the existing assertion or
  gate detects it. A test may merely repeat its mock, import abandoned code,
  or hide a subprocess/checker failure. Restore mutations after the experiment.
- For shared setup or pruning, map distinct assertions to their retained
  scenarios. Preserve malformed inputs, cancellation, cleanup failure,
  permissions, capacity, identity, and meaningful concurrency interactions.
  A faster run that skips a case or weakens its oracle is not an improvement.
- For provider coverage, separate fake-producer, boundary, and actual-engine
  evidence. Inspect named skips and prerequisites; fixtures do not establish
  real Ghidra, LLDB, browser, or other provider behavior.

Classify findings as reproduced defects, supported costs, hypotheses, or
unavailable evidence. Record the baseline command, observed output/exit status,
expected result, affected scope, and competing explanation. A failure on main
may be pre-existing; that does not by itself make it irrelevant to a CI audit.
Attribute PR failures using the executed revision and a clean baseline, not
just their resemblance to a previous failure. Retry only to test a specific
transient explanation; retain the original failure and stop when repetition
adds no evidence. A passing retry does not establish a root cause or a fix.

## Assess efficiency without losing the gate

Read [measurement and CI checks](references/measurement-and-ci.md) when
investigating slowness, caching, runner waits, shared artifacts, or log noise.
Compare equivalent completed work before claiming a speedup. Distinguish
setup/build time, test execution, coverage instrumentation, dependency waits,
and runner scheduling; state which costs remain unmeasured.

Prefer removing proven duplicate preparation, reusing immutable setup, and
reducing repeated subprocess work before shrinking correctness coverage.
Preserve independent sessions where lifecycle or concurrency is the oracle.
Keep live tests fresh; a cached previous pass cannot validate current host,
installed provider contents, permissions, or external state.

## Fix, verify, and hand off within scope

If implementation is authorized, make the smallest structural change at the
owning boundary and add a regression that fails on the baseline for the right
reason. Retest affected consumers and meaningful negative paths; verify cache
invalidation or discovery when those mechanisms change. Read the installed
Turbo documentation before changing its configuration or commands.

Run the repository's applicable checks and inspect complete current-head CI
results before an authorized merge. Preserve required coverage and discovery
gates. Do not suppress a failure, add blanket retries, raise timeouts, or delete
distinct assertions solely to make CI green. Changes to these controls need
their own demonstrated reason and retained failure detection.

Report each confirmed issue with exact revision, reproduction, consequence,
proposed correction, and validation limits. Report performance with workload
and measurements, not just a percentage. Use English issue/PR records when
requested; follow the user's assignment, commit identity, review, and merge
preferences without assuming them for other users. Open ready-for-review PRs
only when that lifecycle is authorized. Resolve necessary review findings and
check final main against the tested tree after merging.

Stop when the authorized work is verified, remaining benefits are unproven,
or further changes would trade correctness for speculative speed. List genuine
uncertainties without turning them into additional optimization rounds.
`````

## 2b. rea-ci-tests-audit reference: measurement-and-ci.md

Source: `.agents/skills/rea-ci-tests-audit/references/measurement-and-ci.md:1-65`

`````markdown
# Measurement and CI checks

## Equivalent completed work

Record the source/workflow SHA, command, test identities and counts, skips,
assertions or output contract, exit status, coverage scope and thresholds,
toolchain/provider versions, host resources, and prepared artifacts. Inspect
both the child result and its report: a profiling wrapper may exit successfully
after the measured command failed. Focused tests can pass while global coverage
thresholds fail; describe both rather than calling the command green.

Measure wall time, user/system CPU, and peak process-family memory for relevant
completed tasks. Parent-only RSS misses workers and their children. On Linux,
summed RSS can double-count shared pages; report RSS/PSS semantics, sampling
interval, missing samples, and observed cleanup limits. Use equivalent host
tools elsewhere. State unknown costs, including agent tokens; fewer log bytes
alone prove neither fewer tokens nor faster tests.

Separate cold execution, warm build/file caches, and warm runtime caches.
Use repeated or alternating runs when variance affects the decision, with
enough observations to distinguish the proposed benefit from noise. Keep
workload, instrumentation, and host conditions comparable; record interference.
A run with fewer tests, early rejection, lost coverage, or a different runner
does not prove suite acceleration. CI-wide claims need end-to-end measurements,
not an extrapolation from one improved family.

## Workflow, caches, and shared artifacts

Trace each reused result from producer to consumers and identify its lifetime.
Check key/input coverage against the actual file inventory and result-affecting
configuration, environment, generated data, tool versions, and host state.
Exercise an affected input change to prove invalidation; exercise an irrelevant
change to support reuse where useful. Cache deterministic preparation and
static analysis only when their inputs fully describe the result.

Verify downloaded artifacts match the expected revision, platform, runtime,
and schema. Check restore misses, failed/partial producers, stale reports,
removed output files, and consumers after producer failures. Shared writers
need output ownership or locks; tests need isolated state, not an unnecessary
global lock. Worker counts do not bound children spawned within each test.
Preserve intentionally concurrent scenarios while bounding unrelated batches.

Check matrix expansion and all job pages before saying CI passed. Inspect
required gates after failed, cancelled, and skipped dependencies. `always()`
alone does not preserve failures; inspect the aggregation logic. Test/report
uploads should retain available diagnostics after failure, while absent or
malformed required results must fail closed. Do not demand an optional report
from a lane intentionally excluded by the selector.

## Runner waits and console noise

Use per-job and per-step timestamps where available. Workflow creation to job
start includes dependencies and other delays; it is not necessarily runner
queue time. Identify when the job became eligible before attributing waits to
runner capacity. If eligibility/queue timestamps are unavailable, report the
combined delay and unknown split. Compare equivalent lanes and runner types
across enough runs; a single busy runner is not a workflow regression.

For console reductions, retain checker exit codes, actionable errors, useful
summary counts, and complete machine-readable artifacts. Verify authored code
remains in the actual checker inventory when excluding generated outputs.
Introduce an authored error as a control; it must still fail. An ignore pattern
can hide real source as well as noise. Show that cached reports are restored,
stale successful reports cannot mask current failures, and report parse errors
remain failures. Measure readability or byte reduction separately from runtime.
`````

## 2c. rea-ci-tests-audit agents/openai.yaml (agent UI metadata)

Source: `.agents/skills/rea-ci-tests-audit/agents/openai.yaml:1-4`

`````yaml
interface:
  display_name: "REA CI and tests audit"
  short_description: "Audit CI/test correctness and measured performance"
  default_prompt: "Use $rea-ci-tests-audit to investigate CI and test correctness, drift, and performance before proposing changes."
`````

## 3. Skill rea-changelog-update

Source: `.agents/skills/rea-changelog-update/SKILL.md:1-134`

`````markdown
---
name: rea-changelog-update
description: Prepare or rewrite REA release changelogs and GitHub release notes from pinned Git history, with verified contributor thanks and Release Please synchronization.
---

# REA changelog update

Use this for release-note preparation and contributor attribution. Read
[docs/releasing.md](../../../docs/releasing.md) from the repository root for
publication authority and the existing checkpoint checks. This skill prepares
notes; it does not authorize merging, tagging, or publishing.

## Inventory before prose

Fetch complete history and tags. Select the published baseline tag from
`.release-please-manifest.json` on the release PR's **base branch**, and pin that
branch's exact SHA as the editorial target. REA tags are `rea-agents-VERSION`.
Use the proposed version, including its prerelease suffix; do not change the
`always-bump-minor` strategy to imitate OpenClaw's calendar versions.

```bash
node scripts/release-notes.mjs inventory \
  --repository morluto/rea --base rea-agents-PREVIOUS \
  --target FULL_BASE_BRANCH_SHA --version VERSION \
  --manifest /tmp/rea-VERSION.contributions.json
node scripts/release-notes.mjs record \
  --manifest /tmp/rea-VERSION.contributions.json \
  --summary \
  --output /tmp/rea-VERSION.record.md
```

Read the inventory, not just the existing bot draft. It includes side-branch
commits, GitHub-associated PRs whose merge commits are in the range, commit
authors/co-authors, and confirmed closing issues with their reporters. GitHub
connections are paginated. Network errors stop generation; rerun into a new
output file after recovery. Existing output files are never overwritten.

Unresolved commit identities are retained as names/emails with `user: null`;
never guess a handle or thank the merger as a substitute. The report preserves
unknowns. This is a reviewed metadata snapshot, not independent proof that a
human authored a patch. For unattributed identities, unusual merge strategies,
backports, reversions, or references that GitHub did not associate, inspect
the source PRs and diffs and report the limitation. The current collector uses
confirmed PR-closing relationships for issue-reporter credit; unrelated issue
mentions are not automatically credited. Do not claim that merely inventoried
work still ships after a revert.

## Write for users and retain credit

Rewrite only the newest `## [VERSION]` section in `CHANGELOG.md`, preserving its
version/date/link heading. Use single-line Markdown list items under:

- `### Highlights`: a few release-defining user outcomes; no quota for small releases.
- `### Changes`: capabilities and meaningful behavior changes.
- `### Fixes`: reliability, correctness, compatibility, and safety fixes.
- `### ⚠ BREAKING CHANGES`: retain when applicable, with migrations and original
  PR/commit references required by the existing checkpoint validator.

Group related work by analyst workflow or user impact. Explain the resulting
behavior in short, concrete entries. Highlights summarize the release; avoid
repeating their full descriptions in Changes. Internal cleanup, tests, CI, and
routine documentation generally belong only in the provenance file. Read ambiguous PRs/diffs before making
claims. Distinguish simulated-provider checks from real-provider verification.

Credit each represented contribution once in the public notes with its link
and `Thanks @...` for its verified human author, known co-authors, and confirmed
closing-issue reporters. Grouping preserves all those credits in one line.
When Highlights, detailed entries or migrations reference the same work,
put its thanks in one of those entries, not all of them. Include issue links.
Direct-commit bullets carry the commit link and known human credit.
Exclude GitHub bots and known agent accounts. REA's observed Anthropic, Cursor
and Codex co-author trailers resolve to `@claude`, `@cursoragent` and `@codex`
with GitHub type `User`; the credit policy excludes them while retaining their metadata.
At the REA maintainer's request, omit `@morluto` self-thanks while preserving
authorship in the inventory. Other human contributors remain eligible.
Use explicit GitHub links for cross-repository references to avoid ambiguous
`#NNN` numbers. Unknown handles stay unknown; they are not fabricated credit.

Append the generated `record --summary` provenance link verbatim at the end
of this release. The linked inventory accounts for every discovered in-range
PR and direct contribution, including internal work omitted from the prose.
Do not paste the full `record` output into public notes: it duplicates thanks
and obscures the user-facing changes. Full records remain available for review.
Do not hand-edit generated credits to make validation pass. Refresh the inventory
when product history changes; a prose-only correction can reuse the snapshot.

## Finalize with Release Please

Before changing the live release PR, have authorization for that PR update.
Local preparation and validation can proceed independently.

1. Add `rea:release-notes-finalized` to the selected open release PR **before**
   editing its branch/body. Main proposal pushes respect this label. This is
   our workflow guard, not Release Please's `autorelease: snooze` mechanism.
   A proposal already running must finish before editing. Do not dispatch
   manual preparation over finalized notes.
2. On that release branch, save the reviewed inventory as
   `docs/releases/VERSION.contributions.json`. This is durable public release
   provenance, not a temporary planning file. Do not add credentials or local
   environment dumps. Keep the existing version artifacts aligned.
3. Run the existing checkpoint validator and the new checker:

   ```bash
   node scripts/release-notes.mjs check \
     --manifest docs/releases/VERSION.contributions.json
   node scripts/release-notes.mjs render \
     --manifest docs/releases/VERSION.contributions.json \
     --output /tmp/rea-VERSION.notes.md
   ```

   The checker supports inline PR bodies, including their surrounding metadata,
   up to GitHub's 65,536-character limit. It fails on larger notes rather than
   truncating credit; Release Please's overflow-link bodies are not integrated.

4. Update the release PR body with the rendered section while preserving its
   Release Please header/footer and component/version structure. Use a body
   file for `gh pr edit --body-file`; changing only `CHANGELOG.md` does not
   change Release Please's release body. Push only authorized changes.
5. Freshly fetch the PR body to a file and run `check --pr-body FILE`. Review
   the complete diff and wait for current CI. Publication checks the body
   again before release creation. Avoid further body edits while publishing.

The finalization label freezes bot refreshes, not main. New product changes
after the inventory target require refreshing the notes before publication.
The workflow checks target ancestry and allows only release metadata paths
after that target. It also requires the inventory target to equal the reviewed
merge's first parent, so intervening main commits require a fresh inventory.
Review diffs within the allowed release metadata paths too: the path guard does
not prove that package dependency/script edits are version-only changes.
To resume automatic proposals, remove the finalization label and let the bot
regenerate; expect editorial changes to be replaced.

Existing releases without a contribution inventory retain their current
publication path. Never retag or republish a package to correct release prose.
`````

## 4. AGENTS.md (repository guidance to coding agents)

Source: `AGENTS.md:1-121`

`````markdown
# Repository Guidelines

## Product and Authority

REA is a local-only reverse-engineering tool with shared CLI/MCP workflows. Distinguish observations, derivations, inferences, and unknowns; preserve Evidence provenance and session semantics through both adapters. Provider support and setup live in [README.md](README.md#choosing-a-deep-analysis-provider) and its linked guides.

Follow the [contribution scope and fail-closed integration rule](CONTRIBUTING.md#contribution-scope). Do not integrate capabilities while material scope, authority, side-effect, or required verification questions remain unresolved. For new providers or capabilities involving target execution, injection, mutation, or protection recovery, seek the required maintainer scope decision before substantial implementation for integration. Welcome early proposals, small exploratory prototypes, and draft PRs that help resolve questions; they do not authorize integration.

Ghidra uses ephemeral databases without modifying executable bytes or controlling a GUI; Windows Ghidra P0 has no mutation authority. IDA analysis is read-only; never save or close an attached GUI database.

Configuration changes must be additive and idempotent, with backups. Installers must not install or upgrade unrelated software, including Homebrew, Node.js, npm, Java, or Ghidra. Ghidra and IDA are bring-your-own. `rea setup` must show its planned changes and require approval before writing files or installing Hopper.

Preserve caller-selected inputs and local evidence, including output, URLs, paths, digests, and metadata. Redact transport authentication credentials and explicitly marked sensitive values; do not infer secrecy from names or text patterns. Do not persist the ambient environment merely because a child inherits it.

## Architecture and Cleanup

Dependencies flow inward: domain semantics and contracts, provider adapters, shared application workflows, then CLI/MCP adapters. Keep engine protocols and provider-specific code out of domain/application layers. See [docs/architecture.mermaid](docs/architecture.mermaid) when changing composition.

Give each interpretation and resource a clear owner. Consumers must use that owner's parsed facts rather than reinterpret raw source. Preserve identity, omission, uncertainty, and source evidence across boundaries. Retain ownership of resources whose cleanup failed. Reuse `src/process/` supervision and identity primitives; a PID and executable path alone do not establish ownership after exit or reuse.

Keep proof of ownership separate from validity, editability, and readiness. Malformed owned data may still be safely removable. Unresolved identity or applicability must remain unknown rather than be treated as absent, foreign, or aligned.

Assess brittleness in touched code during implementation, debugging, review, and maintenance. Fix the producing representation or ownership rule before adding downstream repairs. Normalize once at the owning boundary using format-aware parsers. Remove superseded representations, aliases, wrappers, and redundant tests after verifying affected consumers. Introduce abstractions only when they remove observed complexity.

When fixing a bug, inspect the producing boundary and affected consumers for duplicated interpretation or unclear ownership. Complete any directly related refactor in the same change and remove superseded code. Passing regression tests alone does not establish that the brittleness is resolved. If related cleanup remains, explain what remains and why.

When addressing a review thread, inspect the producing boundary and affected consumers for brittleness. Complete directly related refactoring in the same change. Before resolving the thread, explain the root cause, structural fix, validation, and any remaining cleanup.

Parse unknown boundary values and model expected failures with the tagged error algebra and `Result`. Preserve partial facts and meaningful failure reasons. Keep identity and lookup values separate from display formatting; preserve source values and explicit unknowns when normalization loses information. Absolute paths, file URLs, and HTTP paths have different semantics.

Validate advertised JSON Schemas after SDK conversion against their declared dialect and actual clients. Bind handlers to named contracts with exact types; catalog ordering must never select an operation or schema.

## Performance

Design analysis workflows and agent interfaces for efficiency from the first
implementation. Correctness, useful answers, Evidence provenance, caller choices,
compatibility and safe resource bounds remain required.

Optimize in this order:

1. Agent tokens and context. Return the smallest sufficient answer with
   necessary provenance, coverage and limitations. Use task selection,
   summaries, paging and retained Evidence where supported; honor requested
   detail and keep complete Evidence accessible. Count the whole task,
   including schemas, extra calls and retries.
2. Analysis time. Reuse validated results and shared work. Cache keys must
   cover result-affecting inputs; define invalidation and lifetime. Validate
   freshness before reporting cached live state as current.
3. CPU and memory. Avoid unnecessary work and copies; bound concurrency,
   retained state and serialization growth.

For changes affecting these costs, measure representative completed tasks and
compare equivalent workflows before and after where available. Report token
usage, elapsed time, CPU time and peak process-family memory. Separate cold
and warm runs, label estimates, and state unmeasured costs. Fewer bytes alone
do not establish fewer tokens or faster analysis.

## Development

Use [.nvmrc](.nvmrc) and `package.json#packageManager` for the pinned toolchain. Cursor Cloud may place older Node.js first on `PATH`; environment setup installs the pinned toolchain under `/usr/local/bin`.

- `npm ci`: install locked dependencies.
- `npm run build:cached`: build the runtime and packaged skill.
- `npm run test:local -- PATH...`: source tests without building.
- `npm run test:focused -- PATH...`: exact tests with their required artifacts.
- `npm run check:fast`: cached typecheck/lint and the pre-push check.
- `npm run docs:check`: validate generated documentation.

Use relevant checks for the change. The complete local gate, `npm run check:pr`, is optional for broad changes or CI diagnosis. See [CONTRIBUTING.md](CONTRIBUTING.md) for development, generated-file ownership, and release conventions.

`docs/public/product-catalog.json`, `docs/verification/managed-conformance-*.json`, and `skills/` are ignored outputs. Edit source contracts and `.agents/skills/reverse-engineer-anything/`, then regenerate as needed. `.cache/mcp-tool-catalog.json` is test metadata; runtime builds and source checking do not consume it. Never commit binaries, provider project documents, credentials, `dist/`, `node_modules/`, or local planning artifacts.

## Tool and Test Changes

For tool design, follow [docs/tool-design.md](docs/tool-design.md): start from the analyst question, reuse existing contracts, preserve caller choices, and return useful evidence inline. Limits must follow real format, protocol, authority, or resource constraints. Account for representation expansion before allocation; derive completeness from examined coverage.

For test changes or provider claims, use [docs/testing.md](docs/testing.md). Prefer real public CLI/MCP workflows, then production-boundary integration, then producer goldens. Keep module tests for distinct semantics stronger workflows cannot reliably reproduce. Preserve malformed-input, cancellation, cleanup, permission, capacity, and target-identity coverage when pruning. Report unverified coverage explicitly; simulated providers do not establish real-provider behavior.

Use Conventional Commit subjects and PR titles. Mark breaking changes with `!` or a `BREAKING CHANGE:` footer. Describe behavior changes, relevant validation, and real-provider verification scope.

## Issue Reports

Follow [issue reporting guidance](CONTRIBUTING.md#reporting-issues) and the matching
issue form. Keep reports concise and cite the smallest useful evidence.
Distinguish observed results, source-derived reasoning, hypotheses, and proposed
checks. Never claim runtime reproduction or measurements you did not perform.
Use `NOT_ENOUGH_INFO` with an explanation for missing narrative answers or evidence.
Incomplete reports, source-only findings, and early feature or design ideas are
welcome when their limitations are explicit; a completed diagnosis or fix is not
required to open an issue.

## Pull Request Readiness

Follow [human ownership and readiness](CONTRIBUTING.md#pull-request-ownership-and-readiness)
when preparing a PR. AI-assisted contributions are welcome; a human must review
and own the final diff, check the validation evidence and its limitations, and
explicitly declare the PR ready for initial maintainer review.

Keep the PR body concise and current, with the concrete problem, observable
outcome, approach, and evidence. Report only checks that actually ran as executed;
distinguish source-derived conclusions, proposed checks, and unavailable coverage.
Address actionable automated review findings and explain disagreements.

Leave the template's **Author readiness** declarations unchecked for the human
owner to complete. Never attest to human review on their behalf. Keep the PR in
draft until the human declares the PR initially ready. Later pushes do not
invalidate that declaration or require another human sign-off. Keep the PR body
and affected validation current as work changes. The readiness check validates
the filled declaration; CI and automated review results do not establish that
human review occurred, maintainer scope approval, or merge permission.

<!-- BEGIN:turborepo-agent-rules -->

# This is NOT the Turborepo you know

Turborepo configuration, task behavior, and CLI commands can vary between installed versions and may differ from your training data. Resolve the `turbo` package from this file's directory or relevant workspace; in monorepos, it may not be visible from the repository root. For example, run `node -p "require.resolve('turbo/package.json')"` from a workspace that depends on `turbo`.

Read `docs/README.md` inside that installed package first, then read the relevant pages from its `docs/` directory before changing Turborepo configuration or commands. Heed deprecation notices. These bundled docs match the installed package version and are available without network access.

This block is written and re-added by `turbo` before repository-scoped commands when an AI agent is detected. In the Turborepo source repository, its template is defined in `crates/turborepo-cli/src/cli/agent_guidance.rs`. Removing the managed block while updates are enabled means a later qualifying invocation will add it again. Set `"agentGuidance": false` in the root `turbo.json` or `turbo.jsonc` to opt out; this does not remove an existing block. Keep the block committed with your work to avoid an uncommitted change on the next agent invocation.
<!-- END:turborepo-agent-rules -->
`````

## 5. docs/tool-design.md (tool-description and contract conventions)

Source: `docs/tool-design.md:1-94`

`````markdown
# MCP tool design

## Decide whether to add a tool

Design around the analyst question. Inspect the current canonical contracts,
provider capabilities, and nearest existing tool before changing the surface.
Extend a tool when intent and result contract match; add one for a distinct
outcome or materially different authority. Public names and semantics remain
provider-neutral, with exact coverage reported per provider.

Keep the catalog complete; report capability/session availability instead of
truncating schemas. Serialized bytes alone do not establish agent usability.

## Choose the tool shape

| Shape                 | Use it for                                  | Result                                                                    |
| --------------------- | ------------------------------------------- | ------------------------------------------------------------------------- |
| `inspect`             | Facts about one target, object, or resource | Relevant fields, locations, and facet availability                        |
| `search` / `list`     | Candidate discovery                         | Stable ordering and context; pagination when the query or format needs it |
| `trace`               | Relationships across evidence               | Typed edges, supporting facts, and unresolved paths                       |
| `compare`             | Explicitly paired artifacts or observations | Identity, comparable coverage, and supported deltas                       |
| `workflow`            | A recurring outcome needing composition     | Inline answer, contributing evidence, and partial facets                  |
| `observe` / `capture` | Runtime behavior                            | Authority, launch/attach effects, lifecycle, and cleanup status           |

These are task shapes, not mandatory prefixes. Name tools for the action and
object callers reason about. Avoid unrelated discovery/execution/mutation modes
inside one tool.

## Prefer primitives; compose workflows

A primitive reports a reusable fact about an identified object or relationship.
A format-specific decoder qualifies; one application's business interpretation
belongs outside the general contract. Expose provider APIs when they add a
useful capability that existing tools cannot express.

Compose a workflow when repeated use demonstrates a multi-source outcome REA
can join without hiding caller choices or uncertainty. Batch homogeneous reads
when that removes repeated work while preserving per-item outcomes. Keep prompts
optional and avoid prescribing call sequences that a direct tool can replace.

Agents can compose experiments with ordinary commands, scripts, and local
fixture servers. Custom orchestration languages, replay engines, or separate
prepare/execute plans need an observed requirement those primitives cannot
satisfy. A plan without execution does not establish runtime behavior.

## Define the contract

- Use strict inputs with explicit target identity and required fields. Preserve
  meaningful target, action, capture, and output choices; remove ignored options
  and repeated permission declarations.
- Return the requested facts inline with artifact/provider identity, source
  locations, Evidence references, coverage, and relevant confidence and
  limitations. Use supported selection, summaries or views when they answer
  the question; preserve access to complete source Evidence and honor existing
  contracts and requested detail. Missing coverage is unknown, not absence.
  Avoid extra lookups solely to understand the answer or its provenance.
- Keep observed, derived, and inferred relationships distinct. Preserve
  unresolved edges and partial provider facts instead of requiring every
  provider to supply the same metadata.
- For caller/callee reads, `relationship_coverage` describes only the
  provider-observed direct relationship set. `complete` means that set was
  returned without a known read limit; it does not claim every possible runtime
  edge. Provider and execution caveats stay in `limitations` and do not imply
  incomplete relationship coverage. Missing coverage remains `unknown`.
- Declare process, filesystem, network, UI, and mutation effects truthfully;
  enforce the requested target and lifecycle.
- Add limits only for real format, protocol, authority, or measured resource
  constraints. Report pagination, truncation, cancellation, and partial failure.
  An assumed agent budget is insufficient justification for a limit.

## Implement and evaluate

Put provider protocols/parsing in adapters and shared CLI/MCP workflows in the
application layer. Share Evidence provenance, unknown projection, and session
retention semantics; matching payloads alone do not establish parity.

Measure the resource before choosing a budget and enforce it before the costly
step. Account for value alternatives, trace-frame products, retained records,
serialization expansion, and temporary-file growth separately. Derive facet
completeness from examined records and exhaustiveness, rather than diagnostic
prose or an empty failure list. Preserve observations independently of cleanup
success.

Update canonical contracts, output schemas, examples, generated artifacts, and
relevant docs together. Verify converted advertised schemas and success,
malformed, unavailable, cancellation, and partial outcomes through affected
consumers. Real-engine claims require the matching provider lane; see
[testing.md](testing.md).

When discoverability changes, evaluate representative broad, direct, and negative
tasks on the intended host. Record host/model/catalog, selected tools, arguments,
errors, retries, and task outcomes. Schema validity and keyword heuristics do not
establish successful tool selection. See [mcp-contracts.md](mcp-contracts.md) for
shipped runtime behavior.
`````

## 6. docs/reverse-engineering-tools.md (objdump/GDB/Rizin/Cutter integration guide)

Source: `docs/reverse-engineering-tools.md:1-81`

`````markdown
# Reverse-engineering tool integrations

REA can call caller-supplied GNU objdump, GDB, and Rizin installations. REA does not install or update these tools. Static objdump/Rizin workflows use the same services from CLI and MCP. GDB's persistent MCP sessions and ephemeral CLI command are available only on Linux. Persistent debugger sessions exist only for the lifetime of the REA MCP server process.

In a shared MCP server, unrestricted Rizin and Cutter commands, GDB console
commands, Rizin debugger start/close, and GDB debugger close retire any active
binary analysis session after the operation. This prevents a fresh analysis
provider from being rebound automatically while command effects may still be
writing. After the command and any background writers have stopped, call
`open_binary` explicitly before continuing analysis. A successful command
response alone does not prove that background writers have stopped. An active
Ghidra analysis session must be closed explicitly before an external mutation
can run.

## GNU objdump

`inspect_with_objdump` and `rea inspect-with-objdump` capture stdout and stderr as inline Evidence. Artifact inspection Evidence records SHA-256 digests before and after the provider call and whether those observed digests differ; this cannot prove the exact bytes consumed if the artifact changes during execution. Choose one artifact operation: `file_headers`, `section_headers`, `symbols`, `relocations`, `dwarf`, `disassemble`, or `disassemble_all`. `disassemble` maps to `-d`; `disassemble_all` maps to `-D` and has different symbol-boundary semantics. The pathless `inspect_with_objdump {"operation":"architectures"}` MCP call or `rea list-objdump-architectures` CLI command maps to `-i` and produces subjectless provider-capability Evidence describing BFD targets compiled into the installed binary, not a guarantee that a target is supported.

For DWARF, REA does not follow local debug links by default. Set `follow_debug_links` to `true` to pass `-WK`; external debug-file identities are not bound to Evidence when following links is enabled. The CLI option is `--follow-debug-links true`. REA clears `DEBUGINFOD_URLS` in the objdump child environment to disable debuginfod network access on GNU binutils versions that do not support `-WE`. The complete raw output is authoritative; REA does not normalize it into a version-independent disassembly schema.

```sh
rea inspect-with-objdump ./program disassemble
rea inspect-with-objdump ./program dwarf --follow-debug-links false
```

Captured stdout and stderr are retained up to a 16 MiB combined limit; `output_truncated` marks output beyond that limit.

## GDB

Persistent GDB sessions, including the MCP workflow and one-shot `rea debug-with-gdb` CLI, are available only on Linux. REA verifies a live inferior's output descriptors through `/proc` before detaching it; it does not claim equivalent descriptor verification on macOS. Windows is also unsupported because owned Job Object cleanup can terminate debugger inferiors. On supported Linux hosts, `start_gdb_session`, `gdb_console`, `gdb_session_status`, and `close_gdb_session` manage a persistent GDB/MI session in MCP. The one-shot CLI requires a caller-selected durable TTY: `rea debug-with-gdb --inferior-tty /dev/pts/7 'file ./program'`. The TTY must remain available after GDB exits so a detached inferior can continue writing. MCP starts GDB with `--nx --quiet --interpreter=mi3`, retries initialization with MI2 if MI3 initialization returns an error and cleanup succeeds, waits for its prompt, and disables auto-loading. Pass optional `inferior_tty` to select the terminal that future inferior runs use; REA configures it before the session becomes ready and checks the exact value with GDB/MI. `gdb_session_status` reports the selected path, whether REA still considers the configuration verified, and whether invalid UTF-8 has been observed in MI bytes (`mi_invalid_utf8`) or stderr (`stderr_invalid_utf8`). Commands that can change the inferior TTY or redirect a run revoke that verification permanently for the session, so close retains GDB ownership if a live inferior remains. Closing a session with one live inferior and a verified TTY automatically detaches the target, which can resume execution; MCP clients receive destructive-operation annotations for this behavior. The console remains unrestricted and can run shell commands, change target state, access files, and use network in the REA process user's security context. Raw MI records and console/target/log streams are returned with Evidence; command output is retained up to 16 MiB and explicitly marked when truncated.

Before a normal close, REA checks for live GDB thread groups. If one remains and a durable `inferior_tty` is verified, REA asks GDB to detach it and confirms the detach before stopping the debugger. Without that sink, select and apply a disposition to each inferior through `gdb_console` (for example, detach or kill as appropriate), then retry close. REA never infers target ownership from a PID or path. When the MCP server shuts down, REA terminates only its directly owned GDB process after confirming no inferior or a sink-backed detach; otherwise it retains the process and its output streams for retry.

```text
start_gdb_session {"inferior_tty":"/dev/pts/7"}
gdb_console {"session_id":"…","command":"file ./program"}
gdb_console {"session_id":"…","command":"info files"}
gdb_session_status {"session_id":"…"}
close_gdb_session {"session_id":"…"}
```

## Rizin

`start_rizin_debug_session` and `rea debug-with-rizin` require an explicit `inferior_tty` on Linux. Rizin launches the target with stdout and stderr routed to that caller-selected TTY and `dbg.exitkills=false`; the target can therefore continue running and writing to the TTY after REA closes the debugger. This is a visible target output effect, and the caller is responsible for selecting a suitable terminal that remains available. Before closing, REA serializes after the active command, parses the structured `olj` descriptor list, detaches only a unique `ptrace://` descriptor, confirms its absence, reads back `dbg.exitkills=false`, and verifies `/proc/<pid>/fd/1` and `/proc/<pid>/fd/2` still identify the selected TTY by device and inode. Any malformed or ambiguous readback keeps the Rizin session owned for retry. Persistent Rizin debugger sessions are unavailable outside Linux because this verification depends on `/proc`.

Persistent command Evidence retains the caller-selected and resolved startup paths in `parameters.launch_provenance`. These paths describe launch provenance, not the current target after unrestricted commands. `rizin_debug_session_status.output_invalid_utf8` reports whether lossy frame decoding has been observed during the session. Command Evidence sets `output_invalid_utf8` only when loss was observed in frames collected for that command, including retained partial output; earlier startup or command frames do not mark later valid output as lossy.

```sh
rea debug-with-rizin --inferior-tty /dev/pts/7 ./program dr
```

`execute_rizin_command` and `rea execute-rizin-command` run one selected command against a local artifact. The one-shot profile uses `-N -q -c`, suppressing user settings and scripts while leaving plugins available. Commands and plugins run with the REA process user's security context and may access files, the network, or perform other actions. REA preserves raw output and does not claim that command-specific JSON has one universal schema.

```sh
rea execute-rizin-command ./program iI
```

Captured stdout and stderr are retained up to a 16 MiB combined limit; `output_truncated` marks output beyond that limit.

## Cutter bridge

Cutter commands use the local REA Python bridge and authenticated loopback messages.
The client and plugin must support the current v2 handshake; older peers are
rejected before dispatch because they cannot preserve cross-caller recovery proof.
The client checks the final encoded request against the bridge's 16 MiB frame
limit before dispatch; an oversized command does not retain a cleanup owner.
Discovery admits at most 256 descriptor candidates and reads and probes at most
eight concurrently. A larger directory reports `bridge_directory_capacity_exceeded`.

Terminal receipts are recovered before another command, including from a new CLI
invocation. A signed status response also confirms completion of older bridge
connections after its UI dispatch, preserving recovery proof for a caller whose
receipt another caller has acknowledged. Neither receipt recovery nor a status
probe retries the original command. Failed acknowledgements remain pending and
block new commands until they can be retried successfully.

## Configuration and coverage

The optional `REA_OBJDUMP_COMMAND`, `REA_GDB_COMMAND`, and `REA_RIZIN_COMMAND` values select executable names or paths; otherwise REA searches `PATH`. Values are passed directly to process spawning, not expanded as shell command lines. Provider versions and capabilities remain unknown until observed from the installed tool and verified in the corresponding real-provider lane.

Provider capture limits are separate from the MCP response budget. A result that fits the provider limit may still exceed the default 10 MiB MCP response budget and return a transport `resource_constraint`. Configure `REA_MCP_MAX_RESPONSE_BYTES` to match a larger client receive buffer when that client supports one; otherwise use retained Evidence/export or complete CLI JSON output. See [MCP response limits](./mcp-contracts.md#tool-results).
`````

