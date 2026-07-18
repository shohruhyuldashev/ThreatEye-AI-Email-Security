# ThreatEye model — `threateye-phish`

The specialised local model that scores email and answers analyst questions.

## Where it runs

Inside the **Ollama** container (service `ollama`), on CPU. It is a derived model built
from `qwen2.5:3b` with an expert system brief baked into it (phishing techniques, malware,
code review, ATT&CK, semantic-intent reasoning, and prompt-injection/jailbreak defence).

The backend calls it per email via the OpenAI-compatible Ollama endpoint. It is **the**
detector: the full model runs on every email by default (`DETECTOR_FAST_PATH=0`). The
deterministic layers (authentication, corpus, themed-domain, injection heuristics) are a
**safety net** that can only raise the score — they never replace the model's analysis.
Set `DETECTOR_FAST_PATH=1` to let clearly-decisive cases skip the LLM for speed on CPU.

```
docker exec ollama ollama ps      # shows the model loaded in RAM while it works
docker exec ollama ollama list    # all installed models
```

## Talk to it directly (shell)

```bash
docker exec -it ollama ollama run threateye-phish:1.2
```

Then chat — ask it to score an email, explain a technique, review a snippet, etc. One-shot:

```bash
docker exec ollama ollama run threateye-phish:1.2 "What is a homoglyph domain attack and how do you detect it?"
```

## Rebuild it from source (the reproducible "package")

Everything needed to rebuild the exact model lives in the repo — this is the small,
git-friendly way to ship it:

```bash
python3 scripts/build_phishing_corpus.py     # MITRE-anchored technique corpus
python3 scripts/build_phish_model.py         # -> threateye-phish:1.2 in Ollama
```

`data/Modelfile.threateye-phish` is the produced Modelfile (the baked-in brief). Rebuilding
needs the `qwen2.5:3b` base available in Ollama.

## Save / restore the trained weights (tar)

The weights are in the `ollama_data` Docker volume, not the image. Archive/restore:

```bash
./scripts/model-archive.sh export           # -> models/threateye-phish-<ver>-<date>.tar.gz
./scripts/model-archive.sh import <file>    # restore into the volume (offline-safe)
docker exec ollama ollama list
```

A **lean archive** (`models/threateye-phish-1.2-*.tar.gz`, ~1.8 GB) contains only
`threateye-phish:1.2` + its `qwen2.5:3b` base — small enough for a GitHub Release asset
(2 GB limit). The private signing key is excluded. Restore with the same `import` command.

> Uploading the weights: they are too large for plain `git` (100 MB limit). Attach the
> `.tar.gz` to a **GitHub Release** (Releases → Draft new release → attach the file), push
> it via **Git LFS** if you have quota, or store it in cloud storage (e.g. Google Drive).
> The tar files are git-ignored on purpose.

## Bounded self-improvement (governed, not autonomous)

`scripts/self_improve.py` lets the model get stronger from real, confirmed data — with hard
limits so it can't spiral out of control:

- Learns only from **analyst-confirmed** verdicts (human ground truth), never from its own
  output — no self-reinforcing runaway.
- Builds a **candidate** and promotes it only if a **validation gate** passes: quality
  thresholds on the labeled dataset (precision ≥ 0.98, recall ≥ 0.80) **and** its
  anti-injection / safety sections are still intact.
- **Hard limits:** runs only with an explicit `--confirm` (never autonomously), caps new
  examples per cycle, refuses to bump past a version ceiling (`1.<max>`), honours a
  kill-switch (`data/SELF_IMPROVE_DISABLED`), and audits every cycle to
  `data/self_improve_audit.jsonl`. A human always makes the final promote decision.

```bash
python3 scripts/self_improve.py --dry-run     # build + check a candidate, never promote
python3 scripts/self_improve.py --confirm      # full cycle; promote only if it passes
```

## Versions

- `1.0` — phishing-specialised (MITRE corpus).
- `1.1` — + malware / code-review / web-network / ATT&CK / IR expertise.
- `1.2` — + semantic-intent reasoning, prompt-injection & jailbreak defence, real-template
  grounding. **Current default.**
