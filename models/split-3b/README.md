# ThreatEye model — `threateye-phish:1.3` (3b)

The specialised 3b phishing-analyst model (base `qwen2.5:3b`), split into ~500 MB parts so
each uploads reliably over a slow link. The model version is `1.3` regardless of which
release tag these assets are attached to.

## Assets

| File | What |
|------|------|
| `threateye-phish-1.3.part-00.bin` … `part-03.bin` | the archive, split into 4 parts (~1.8 GB total) |
| `SHA256-full.txt` | sha256 of the reassembled `.tar.gz` (for integrity) |

## Restore & use

```bash
# 1. Download all four .bin parts + SHA256-full.txt into one folder, then reassemble
#    (the parts concatenate in filename order):
cat threateye-phish-1.3.part-*.bin > threateye-phish-1.3.tar.gz

# 2. Verify integrity (must match SHA256-full.txt):
echo "$(cat SHA256-full.txt)  threateye-phish-1.3.tar.gz" | sha256sum -c
#    -> threateye-phish-1.3.tar.gz: OK

# 3. Import into Ollama. From the ThreatEye repo:
./scripts/model-archive.sh import threateye-phish-1.3.tar.gz

#    …or without the repo, straight into the ollama volume:
#    docker run --rm -v <ollama_data_volume>:/to -v "$PWD":/from alpine \
#      sh -c "tar xzf /from/threateye-phish-1.3.tar.gz -C /to"
#    docker restart ollama

# 4. Confirm it loaded:
docker exec ollama ollama list        # should list threateye-phish:1.3
```

## Run it

```bash
# Chat with it directly (email scoring as JSON, or ask security questions in prose):
docker exec -it ollama ollama run threateye-phish:1.3
```

In the app: **Settings → AI Engine → Model** = `threateye-phish:1.3`.

## Rebuild instead of download

The archive holds `threateye-phish:1.3` + its `qwen2.5:3b` base (no private key). If you
have the repo and `qwen2.5:3b` in Ollama, you can skip the download and rebuild the exact
model:

```bash
python3 scripts/build_phishing_corpus.py
python3 scripts/build_phish_model.py         # -> threateye-phish:1.3
```
