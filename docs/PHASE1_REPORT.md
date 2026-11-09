# VulnFix-RL Phase 1 Report — funnel prototype, verifier, audit

Date: 2026-11-06. Scope: Phase 1 of SPEC_v0.1.md only (construction
pipeline + verifier + degenerate-battery audit). No training run, no
publishing, no spend ($0; all work local in this sandbox).

## Headline result

**Gate status: FAILED (one criterion unmet), with the failure isolated
and evidenced.** The preregistered ClaimWork gate is gold mean 1.0 AND
zero battery false passes. After two audit runs and four source fixes
(below), the current audit (`build/audit_phase1.json`) records:

- gold mean reward **1.0**, gold passes on all 11 instances;
- battery false passes **1** (setuptools-cve-2025-47273, item 9) — so
  `gate_pass` is **false**. The gate was not widened and the tolerance
  was not moved. The remaining false pass is described in §5.

**11 verified instances** (target 20; the shortfall is reported, not
padded — see §2). 4 CWE-89 + 7 CWE-22, across 5 projects.

## 1. What was built

- `src/mining.py` — candidate mining from GHSA/OSV for Python CWE-89 /
  CWE-22, with fix-commit resolution (OSV GIT ranges/references →
  `git log --grep` → a small hand-checked override table).
- `src/funnel.py` — the Section 4 funnel in order (licence → build →
  PoC 3/3 → gold → mutants ≥3 → leak), per-candidate JSON log at
  `build/funnel_log.jsonl`.
- `src/verifier.py` — Section 5 exactly: 0.25 visible PoC + 0.35
  mutants (prorated) + 0.25 regression + 0.15 minimality; pass ≥ 0.85
  AND both exploit components full AND no tamper flag; hard-zero for
  diffs touching tests/PoC/CI/dependency manifests; payload
  special-case rule; gained-exception-swallow rule.
- `src/battery.py` + `src/audit.py` — the 10-item degenerate battery
  (item 10 = gold control) graded against every verified instance;
  audit history preserved in `build/audit_runs/`.
- `tests/test_verifier.py` — pytest suite (§6).
- `data/<instance>/` — 11 verified packages (instance.json with frozen
  mutant list and baseline, poc.py, brief.txt, gold_patch.diff).

## 2. Funnel accounting (measured, from build/candidates.jsonl and build/funnel_log.jsonl)

| Stage | Count | Notes |
|---|---|---|
| Advisories mined | 105 unique CVEs | 22 CWE-89, 83 CWE-22; 21 seed packages |
| Triage discards | 56 | recorded reasons: server-level PoCs / very large dependency stacks (34), LLM-chain scaffolding (5), copyleft licence (5), era/platform (12) |
| Shortlisted | 49 | django, aiohttp, mako, piccolo, pip, setuptools, gitpython, dulwich |
| Fix-commit resolution discards | 21 | no fix commit in OSV ranges or git history (incl. all dulwich entries; pip CVE-2026-1703 / CVE-2026-8643) |
| Resolved | 28 | +1 (CVE-2025-59682) resolved by hand from git history during instance authoring |
| Attempted end-to-end | 11 | **all 11 verified** |
| Manual discards | 5 | piccolo CVE-2023-47128 (PoC needs a multi-statement Postgres driver; none in sandbox), django CVE-2025-59681 (MySQL/MariaDB-only), CVE-2025-13372 (PostgreSQL-only), CVE-2024-53908 (Oracle-only), CVE-2026-1207 (GDAL/GEOS unavailable) |
| Deferred to Phase 2 | 13 | resolved but not attempted: mostly 2019–2022-era instances; CVE-2026-1312 (no crisp unit-level oracle established) |

Measured yield: 11 verified / 105 mined (10.5%); 11 / 29 resolved
(38%). pip contributed 0 verified instances (its one in-scope resolved
candidate is 2019-era and deferred; the recent pip entries had no
resolvable fix commit, and CVE-2025-8869 is classified CWE-61 by OSV,
outside the CWE-89/22 filter).

## 3. Verified instances

| Instance | CVE | Repo | CWE | Gold patch | Mutants frozen | Pinned-suite baseline (gold suite on vuln source) |
|---|---|---|---|---|---|---|
| django-cve-2025-64459 | CVE-2025-64459 | django | 89 | +9/−0, 2 files | 6 | 33 tests, 0 failed |
| django-cve-2026-1287 | CVE-2026-1287 | django | 89 | +6/−4, 1 file | 4 | 91 tests |
| django-cve-2025-57833 | CVE-2025-57833 | django | 89 | +1/−0, 1 file | 6 | 150 tests |
| django-cve-2024-42005 | CVE-2024-42005 | django | 89 | +2/−0, 1 file | 6 | 6 tests |
| django-cve-2024-39330 | CVE-2024-39330 | django | 22 | +14/−4, 2 files | 4 | 183 tests |
| django-cve-2025-59682 | CVE-2025-59682 | django | 22 | +5/−1, 1 file | 4 | 3 tests |
| aiohttp-cve-2024-23334 | CVE-2024-23334 | aiohttp | 22 | +14/−4, 1 file | 4 | 31 tests |
| aiohttp-cve-2025-69226 | CVE-2025-69226 | aiohttp | 22 | +9/−9, 1 file | 4 | 150 tests |
| gitpython-cve-2023-41040 | CVE-2023-41040 | gitpython | 22 | +2/−0, 1 file | 3 | 14 tests, 4 baseline failures* |
| mako-cve-2026-41205 | CVE-2026-41205 | mako | 22 | +1/−3, 1 file | 4 | 10 tests |
| setuptools-cve-2025-47273 | CVE-2025-47273 | setuptools | 22 | +16/−2, 1 file | 4 | 20 tests, 1 baseline failure† |

\* gitpython baseline failures are deterministic sandbox artefacts
(tests that inspect the checkout itself, which is a detached-HEAD
worktree); identical across repeated runs and on both commits.
† setuptools baseline failure is one pre-existing fixture error
(`tmp_home_dir` fixture unavailable) present on both commits.

Baseline semantics: the pinned suite is the **gold commit's test
files** run against the vulnerable source (see defect D2).

## 4. Amendment recorded

SPEC_v0.1.md Amendments, 2026-11-06: the regression suite is the test
module(s) relevant to the vulnerability, pinned per instance, not the
repo's full suite (full suites do not run end-to-end in this sandbox);
baseline failures are recorded in the instance package and the
criterion remains "no new failures".

## 5. Audit history and defects found (ClaimWork loop)

**Audit run 1** (`build/audit_runs/audit_phase1_20261106T194702.json`):
gold mean 0.90, 3 battery false passes → gate FAILED. Four defects
were found, fixed at the source, and the funnel + audit were re-run in
full:

- **D1 — mining undercount (found before the audit).** OSV GHSA
  entries carry CWE ids but the PYSEC entries carry the GIT fix
  ranges; filtering entry-by-entry discarded the PYSEC entries and
  lost known fix commits. Fixed by grouping all entries per CVE before
  filtering. Resolution count rose 23 → 28.
- **D2 — regression baseline penalised gold for upstream test
  changes.** The gold commits for django-cve-2024-39330 and
  django-cve-2026-1287 also update existing tests that asserted the
  vulnerable behaviour; grading with the vulnerable commit's suite
  scored gold 0.75 on both. Fixed with SWE-bench semantics: the gold
  commit's test files are overlaid onto baseline and graded runs
  (`snapshots.overlay_gold_tests`); the baseline is that suite's
  failures on the vulnerable source. Candidate patches touching tests
  are still hard-zeroed before the overlay, so it cannot be gamed.
- **D3 — exception-swallow check flagged pre-existing handlers.** The
  scan covered the whole touched file; setuptools' gold patch was
  flagged for a handler that pre-dates it in package_index.py. The
  SPEC penalty is for what the patch *adds*; the check now counts only
  swallow signatures absent from the vulnerable version of the file. A
  unit test pins this behaviour.
- **D4 — instance visible payload copied from the gold diff.**
  setuptools' visible payload was the exact URL the fix adds as a
  regression doctest, so the gold patch itself tripped the
  payload-special-case rule. Fixed by choosing a payload disjoint from
  the gold diff, and by adding a funnel leak-stage check (visible
  payload vs gold diff) so this class is caught at construction.
- **D5 — battery item 9 deny-lists built on channel invariants.**
  Three item-9 false passes (aiohttp-cve-2025-69226, django-cve-2024-
  42005, mako-cve-2026-41205) came from `brief_strings` that every
  mutant must contain by construction (the `data__` field prefix; the
  URL-decoded `/st/../` form). Fixed in the instance definitions: each
  brief now carries a concrete example payload, and `brief_strings`
  are fragments of that example that the frozen mutants do not share.
  All three items fail after the fix.
- PoC defects caught by the funnel during construction (all fixed in
  the PoCs, funnel re-run): django-cve-2024-39330's escape target sat
  in a shared parent directory, so a file left by a vulnerable-code
  run made a gold-code run look exploited (PoC nesting fixed);
  django-cve-2025-57833 / CVE-2024-42005 PoCs initially executed the
  injected query (backend-specific outcome) instead of using the
  deterministic compile-level oracle; django-cve-2025-59682's PoC
  needed the second benign archive member the fix's own regression
  test uses (a single member is treated as a shared leading directory
  and stripped, masking the traversal); the funnel's MIT licence
  needle ("MIT License") false-negatived Mako/setuptools, whose
  licence files carry the MIT body without the title line (needle is
  now the permission-grant sentence).

**Audit run 2** (`build/audit_phase1.json`, current): gold mean
**1.0** (11/11 gold pass), battery false passes **1**:

- **Remaining false pass: setuptools-cve-2025-47273, item 9
  (deny-list from brief).** The brief's example strings are `%2f` and
  `escape.txt`; jointly they cover all four frozen mutants (every
  mutant uses a `%2f`-encoded separator or resolves to the example
  filename). The item scores 1.0. This is an instance-design weakness
  of the same family as D5, not a verifier-code defect: the verifier
  cannot distinguish the deny-list from a fix because the mutant set
  does not contain a surface outside the two example strings. The
  correct remedy is a more diverse frozen mutant set for this instance
  (validated through the funnel, as the other D5 fixes were); it has
  **not** been applied in this run, so the gate stands FAILED on this
  single item rather than the pass being engineered by narrowing the
  check. Battery taxonomy over run 2 (99 items): no-op 11, deletion
  22, payload-special-case 25, test-tamper 11, exception-swallow 5,
  other 24, pass 1 (the item above).

Also observed in run 1 and recorded without a fix, because the pass
gate already fails these items: battery item 4's special-case
transform on django-cve-2026-1287 is not flagged
`payload_special_case` — the visible payload contains a control
character whose source-escaped form evades the raw/normalised literal
match. The item still fails (mutants unblocked), but the taxonomy
undercounts special-casing for payloads with non-printable characters.

## 6. Tests run

- `~/workspace/vulnfix-rl/.venv/bin/python -m pytest tests/ -q
  --no-header -p no:cacheprovider -o addopts=` → **11 passed, exit
  code 0** (verifier unit tests: diff parsing, path classification,
  tamper detection, payload special-case raw/decoded/normalised forms,
  gained-swallow semantics, reward constants; funnel invariants:
  mutant determinism, stage ordering for all verified entries in
  `build/funnel_log.jsonl`, package completeness).
- Funnel: `python3 -m src.funnel <11 instance ids>` → 11/11 verified
  (final run after D2–D5 fixes).
- Audit: `python3 -m src.audit` → run 1 gate FAILED (0.90 / 3 false
  passes), run 2 gate FAILED (1.0 / 1 false pass); JSON in `build/`.

## 7. Honest not-verified list

- **The release gate does not pass.** Gold mean is 1.0 but one battery
  false pass remains (setuptools item 9, §5). Any Phase 2 use should
  treat the gate as unmet until that instance's mutant set is
  diversified and the audit is re-run in full.
- Network egress for graded runs is discouraged only by deliberately
  broken proxy environment variables — an env-level guard, **not** an
  OS-level network namespace. Nothing in Phase 1 verifies isolation
  beyond that.
- Verified packages do not embed the repository snapshots;
  `instance.json` records the repo URL and the vulnerable/fix commits,
  and worktrees materialise under `work/snapshots/` from local clones
  in `work/repos/`. Rebuilding elsewhere requires re-cloning.
- aiohttp-cve-2025-69226's PoC oracle is routing-acceptance
  (resolve() matching), mirroring the fix's own regression test; it
  does not demonstrate file contents being returned. It is the only
  instance whose oracle is below data-return strength.
- Django alias-family PoCs (CVE-2025-64459, CVE-2026-1287,
  CVE-2025-57833, CVE-2024-42005) use a compile-level oracle (the
  crafted alias reaches the generated SQL / is rejected at compile
  time); executing the injected statement is backend-specific and was
  deliberately not used as the signal.
- Splits (train/test/OOD), cross-file difficulty targets, and the
  120/40/40 dataset sizes from the SPEC are Phase 2+ work; Phase 1's
  11 instances are a funnel prototype yield, not a split.
- No human has reviewed the PoCs or the verifier code outside this
  build process.

## Addendum (2026-11-06, audit run 3): Phase 1 gate PASSED

After the run-2 report above was delivered, the one remaining battery
false pass (setuptools CVE-2025-47273, item 9) was fixed by mutant
diversification only -- no verifier rule, weight, threshold, or battery
transform changed. The instance's mutator payloads now include
uppercase-`%2F` payloads with filenames the brief never shows
(`%2Fhome%2Fuser%2F.ssh%2Fauthorized_keys`, `%2F..%2Fsecret.bin`,
`%2Fdata%2Fsecrets%2Fpwned.bin`); each was screened against both
snapshots (exit 0 on vulnerable, exit 1 on gold) and the instance was
re-run through the full funnel (verified, 5 surviving mutants). A
single-instance audit re-check gave gold 1.0, battery false passes 0,
item 9 reward 0.79.

Full audit re-run (run 3, `python3 -m src.audit`, exit code 0,
2026-11-06T20:03Z, recorded in `build/audit_phase1.json`, runs 1-2
archived in `build/audit_runs/`):

- gold_mean: 1.0
- gold_all_pass: true (11/11 instances at reward 1.0)
- battery_false_passes: 0
- gate_pass: true

Phase 1 is complete at 11 verified instances (target 20; shortfall
stands as reported in the funnel counts above, the bar was not
lowered). Spend remained $0. Phase 2 (dataset scale to the SPEC
Section 6 targets plus the calibration panel) is not authorised by
this addendum and waits on a separate go.
