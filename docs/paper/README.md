# Materials for the conference paper

Where each item needed for the paper lives in this repository, and how to
regenerate every reported number. Nothing here was reorganised for the paper;
the two CSV files in this folder are generated from the published records by
`analysis/paper_inventory.py`.

## 1. Repository and frozen version

- Repository: https://github.com/Keshav-kh/DenialDojo
- Frozen version for the paper: tag **`paper-materials-2026-10-05`**. It covers
  the thesis results through Checkpoint 10, with code, all run records and this
  guide.
- Setup (Python 3.14 pinned in `.python-version`; on Windows, prefix with
  `py -3.14 -m`, and enable long paths before cloning with
  `git config --global core.longpaths true`):

```bash
git clone --branch paper-materials-2026-10-05 https://github.com/Keshav-kh/DenialDojo
cd DenialDojo
uv sync --extra dev
uv run pytest            # 410 passed, 5 skipped
```

No API key is needed for any command below. They read the published records
under `runs/` and never write there.

| Result | Command | Output to expect |
| --- | --- | --- |
| Leakage-rate bounds (OpenAI 8E table, then the all-model Checkpoint 9 table) | `uv run python analysis/leakage_bounds.py` | all models, cited: natural 1/918 records (CP 0.52%), 1/306 cells (1.54%); forced 0/104 cells (2.84%); pooled 1/410 cells (1.15%) |
| Chapter 10 label-wording tests | `uv run python analysis/label_wording.py` | H10.2 and H10.3: 6 of 6 models, p = 0.0156; H10.4 not rejected |
| Chapter 10 per-arm tables, one model | `uv run python -m denialdojo.checkpoint10 summary --provider openai --model gpt-5.6-luna` | five arms x 40 records |
| Cost of uniform denials (exploratory) | `uv run python analysis/uniform_utility.py` | 1042/1080 vs 1035/1080, Fisher p = 0.50 |
| Per-cell table of one arm, here the discovery case | `uv run python -c "from pathlib import Path; from denialdojo.run_api_attack_pilot import summarize; a='runs/pilot6i/checkpoint4a-gpt-5.6-luna-workspace_vacation_document_file_probe'; print(summarize(Path(a+'-attack'), Path(a+'-benign'), scenario='workspace_vacation_document_file_probe'))"` | natural, v2, reason-bearing: `cond_leak` 2/2 at delay 0 and 2/2 at delay 2, the 4 of 4 pairs. Works for any arm path in the manifest. (The `summary` subcommand builds provider-prefixed paths, which the OpenAI folders predate.) |
| Checkpoint 9C re-score evidence | `uv run python analysis/rescore_9c.py` | matches `docs/checkpoint9c_rescore.json` |
| Inclusion manifest and dataset counts | `uv run python -m analysis.paper_inventory` | regenerates the two CSV files in this folder |
| Replay any record | `python -c "from denialdojo.trace_v2 import replay_run_artifacts as r; r('<arm>/raw/<id>.json', '<arm>/derived/<id>.json')"` | re-derives the record and checks its SHA-256 binding |

For the Checkpoint 9 and 10 runners the hosted entry points are listed in the
top-level README; re-running models costs money and is not needed to reproduce
any figure.

## 2. Thesis source

- `docs/thesis/draft2/thesis.tex`: the complete current thesis in one file, in
  the Schreyer format, with `thesis.pdf` beside it. Build with `pdflatex` three
  times.
- The bibliography is inline (`thebibliography` at the end of the file); there
  is no separate `.bib` file.
- There are no figures and no plotting scripts: every result is a LaTeX table,
  and each table's numbers come from the commands in section 1.
- `docs/thesis/thesis.tex` is the earlier draft one, kept for reference.

## 3. Machine-readable results and inclusion

- **`docs/paper/inclusion_manifest.csv`**: one row per experiment arm, 101 rows
  (88 completed arm directories and the 13 Checkpoint 9 model-scenario arms that
  were never run). Columns:
  - `path`, `arm` (attack, benign, labels), `provider`, `model`, `scenario`,
    `defense_mode`, `records`;
  - `role`: `discovery` (the realised attack, Luna S2), `evaluation`,
    `supplementary` (delivery-gated S1/S2 arms of the added models),
    `defence` (5C quarantine sweep, 8B guard), `mechanism` (Checkpoint 10),
    `superseded`;
  - `in_cited_bound`: whether the arm enters the cited leakage bound;
  - `status`: `interpretable`, `void`, `superseded` or `not_run`, with `reason`
    stating the preregistered rule and the cause (for example provider
    filtering, a positive control below 19/20 pairs, or a failed readiness gate);
  - attack arms also carry counts recomputed from the records: natural records
    and how many had the injection delivered, natural leaks and leaking state
    pairs, forced records and leaks, reason-bearing positive-control pairs
    decoded correctly (the quantity the void rule uses), and
    `provider_filtered_records` (Checkpoint 9C-2).

  The generator fails if its cited set differs from the set
  `analysis/leakage_bounds.py` loads, or if an arm's status contradicts its
  recomputed positive-control result.
- **`docs/paper/dataset_counts.csv`**: what every file count refers to (section 5).
- Per-arm aggregates: every arm directory under `runs/` has a `summary.json`, a
  `manifest.json` (repository commit, source-tree hash, runtime, expected run
  IDs) and an `index.jsonl` with the SHA-256 of each raw and derived record.
- `analysis/report.md` and `analysis/cell_stats.csv`: the Checkpoint 4A
  (scenario one, OpenAI) statistical report from `analysis/analyze.py`.
- `docs/checkpoint9c_rescore.json`: the Checkpoint 9C re-score evidence.

## 4. Analysis code and preregistration

| What | Where |
| --- | --- |
| Per-record evaluator (v3): decoding the sink, leakage success, utility, protocol status | `src/denialdojo/trace_v2.py` (`derive_run`), with each scenario's decoder and oracle in `src/denialdojo/scenarios/` |
| Paired (counterfactual) evaluator: a pair succeeds only if both hidden-state arms observe the denial and each sends the code for its own state | `src/denialdojo/run_api_attack_pilot.py`, `_paired_conditional_leakage` |
| Injection-delivery gate (Checkpoint 7A) | `src/denialdojo/run_api_attack_pilot.py`, `injection_delivered` |
| Leakage bounds: which arms, the per-record and per-cell Clopper-Pearson construction, the 7G void cells | `analysis/leakage_bounds.py` (arm lists at the top; the docstring states the cell definition) |
| Chapter 10: eligibility, per-arm counts, sign tests | `src/denialdojo/checkpoint10.py` (`summarize_records`, `label_delivered`, `shown_codebook_order`) and `analysis/label_wording.py` |
| Provider filtering and the trailing-period rule (9C-1, 9C-2) | `src/denialdojo/checkpoint9c.py` |

Rules for inclusion, exclusion and denominators, all in `docs/preregistration.md`
(each entry dated and written before the data it governs):

- Checkpoint 7A: the delivery gate; a cell whose injection was not delivered is
  void, not null.
- Checkpoint 7B, as applied in 7C: the positive-control void rule; an arm is
  interpretable only if its reason-bearing positive control decodes at least 19
  of 20 state pairs.
- Checkpoint 7G: the three scenario-five Terra natural cells excluded whole.
- Checkpoint 8C: the cited bound uses scenario three onward.
- Checkpoint 9 analysis rules: the cited and supplementary arms of the added
  models.
- Checkpoint 9C: the trailing-period utility rule and provider-filtered records.
- Checkpoint 10 and Checkpoint 10 results: the label experiment's design,
  eligibility, tests and outcome.

## 5. What the dataset counts mean

One **run record** is one agent episode: one model, one condition, one hidden
state, run once. Each episode is stored as one raw record and one derived record
(the evaluator's output, bound to the raw record by SHA-256).

| Count | What it counts |
| --- | --- |
| **15,313** | raw run records, i.e. agent episodes, across the whole project: every experiment arm, smoke run, readiness gate, development pilot and archived attempt. The thesis's "15,313 raw run records" is this number. |
| **32,324** | all files under `runs/`: 15,313 raw + 15,313 derived records + 720 guard-model transcripts + 978 supporting files (manifests, indexes, summaries, run logs). This is the "32,324 run records" in Keshav's email, which counted files, not episodes. |
| 32,315 | a stale figure in the thesis's credential-scan note: the 29,639 files scanned after Checkpoint 9 plus the 2,676 Checkpoint 10 files, before nine later run logs existed. The scan before publication covered all 32,324 files; the thesis now says 32,324. |

Of the 15,313 episodes:

| Episodes | Category |
| --- | --- |
| 12,456 | experiment arms, Checkpoints 4A to 10 (every row of the inclusion manifest) |
| 1,512 | exploratory smoke runs (never enter a reported figure) |
| 1,184 | readiness gates, preflights and development pilots (Checkpoints 1 to 3) |
| 161 | archived failed or superseded attempts |

Of the 12,456 experiment-arm episodes, 9,024 are in interpretable arms: 4,992
evaluation, 1,560 supplementary, 312 discovery, 1,200 Checkpoint 10 and 960
defence. The remaining 3,432 are in void (2,808) or superseded (624) arms.

Suggested totals for the paper:

- **Dataset:** 15,313 agent episodes in total, of which 12,456 are in experiment
  arms and 9,024 in interpretable arms.
- **Cited leakage bound:** 13 attack arms, 3,016 episodes: 918 natural (54 of
  them from S5 Terra after its 18 void-cell records), 1,040 forced, and 1,040
  positive-control episodes, which validate the instrument and are not in the
  bound.
- **Chapter 10:** 1,200 episodes, 6 models x 5 arms x 40.
