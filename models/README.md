# Model archives

`threateye-phish-1.1-20260718.tar.gz` is a gzipped copy of the `threateye-ai-email-security-120_ollama_data` Docker volume, containing
the Ollama model store — including the specialised **threateye-phish:1.1** and the base model it
was derived from.

Restore on any machine (no internet needed):

    ./scripts/model-archive.sh import models/threateye-phish-1.1-20260718.tar.gz
    docker compose up -d ollama
    docker exec ollama ollama list

Then point **Settings → AI Engine → Model** at `threateye-phish:1.1`.

Rebuild it from source instead:

    python3 scripts/build_phishing_corpus.py
    python3 scripts/build_phish_model.py
