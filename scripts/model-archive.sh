#!/usr/bin/env bash
#
# Archive / restore the ThreatEye phishing model.
#
#   ./scripts/model-archive.sh export            # -> models/threateye-phish-<ver>.tar.gz
#   ./scripts/model-archive.sh import <file>     # restore into the ollama volume
#   ./scripts/model-archive.sh list              # what's in the volume right now
#
# Why a volume archive rather than `docker save`:
# `docker save` captures the ollama *image*, which does not contain any model — the
# weights live in the `ollama_data` volume. Archiving the volume is what actually
# preserves `threateye-phish:1.0` (and the qwen2.5 base it is derived from), so the
# specialised model survives `docker compose down -v`, a host rebuild, or a move to
# another machine that has no internet to re-pull from.
set -euo pipefail

cd "$(dirname "$0")/.."
PROJECT="$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
VOLUME="${OLLAMA_VOLUME:-$(docker volume ls --format '{{.Name}}' | grep -E 'ollama_data$' | head -1)}"
OUTDIR="models"
MODEL="${MODEL_NAME:-threateye-phish:1.1}"

[ -n "$VOLUME" ] || { echo "could not find an ollama_data volume; set OLLAMA_VOLUME"; exit 1; }

case "${1:-}" in
  export)
    mkdir -p "$OUTDIR"
    VER="$(echo "$MODEL" | tr ':/' '-')"
    OUT="$OUTDIR/${VER}-$(date -u +%Y%m%d).tar.gz"
    echo "volume : $VOLUME"
    echo "output : $OUT"
    # Stream the volume out through a throwaway alpine so nothing depends on the
    # ollama image staying around.
    #
    # id_ed25519* is Ollama's own signing keypair, generated per install. It is not
    # needed to run a model and this archive is meant to be copied between machines,
    # so excluding it keeps a private key out of something you might hand to someone.
    docker run --rm -v "$VOLUME":/from -v "$PWD/$OUTDIR":/to alpine \
      tar czf "/to/$(basename "$OUT")" -C /from --exclude='./id_ed25519*' .
    ls -lh "$OUT" | awk '{print "size   :", $5}'
    cat > "$OUTDIR/README.md" <<EOF
# Model archives

\`$(basename "$OUT")\` is a gzipped copy of the \`$VOLUME\` Docker volume, containing
the Ollama model store — including the specialised **$MODEL** and the base model it
was derived from.

Restore on any machine (no internet needed):

    ./scripts/model-archive.sh import $OUT
    docker compose up -d ollama
    docker exec ollama ollama list

Then point **Settings → AI Engine → Model** at \`$MODEL\`.

Rebuild it from source instead:

    python3 scripts/build_phishing_corpus.py
    python3 scripts/build_phish_model.py
EOF
    echo "wrote  : $OUTDIR/README.md"
    ;;

  import)
    SRC="${2:-}"
    [ -f "$SRC" ] || { echo "usage: $0 import <archive.tar.gz>"; exit 1; }
    echo "restoring $SRC into volume $VOLUME"
    docker compose stop ollama >/dev/null 2>&1 || true
    docker volume create "$VOLUME" >/dev/null
    docker run --rm -v "$VOLUME":/to -v "$PWD/$(dirname "$SRC")":/from alpine \
      sh -c "tar xzf /from/$(basename "$SRC") -C /to"
    docker compose up -d ollama >/dev/null
    sleep 4
    docker exec ollama ollama list || true
    ;;

  list)
    docker exec ollama ollama list
    ;;

  *)
    sed -n '2,12p' "$0"
    exit 1
    ;;
esac
