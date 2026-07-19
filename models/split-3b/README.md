# threateye-phish:1.3 (3b model) — split archive

The full model archive (`threateye-phish-1.3-*.tar.gz`, ~1.8 GB) is split into ~500 MB
parts so each uploads reliably over a slow/unstable connection — a single 1.8 GB upload
was failing mid-transfer with GitHub's "can't process that file".

## Parts

- `threateye-phish-1.3.part-00.bin`
- `threateye-phish-1.3.part-01.bin`
- `threateye-phish-1.3.part-02.bin`
- `threateye-phish-1.3.part-03.bin`
- `SHA256-full.txt` — sha256 of the reassembled `.tar.gz`

Attach all of these to a GitHub Release (Releases → Draft new release → attach files).

## Restore (download all parts, then)

```bash
# 1. reassemble (parts concatenate in order)
cat threateye-phish-1.3.part-*.bin > threateye-phish-1.3.tar.gz

# 2. verify integrity
sha256sum -c <<< "$(cat SHA256-full.txt)  threateye-phish-1.3.tar.gz"

# 3. import into Ollama (offline-safe)
./scripts/model-archive.sh import threateye-phish-1.3.tar.gz
docker exec ollama ollama list      # should show threateye-phish:1.3
```

The archive holds `threateye-phish:1.3` + its `qwen2.5:3b` base (no private key).
