#!/usr/bin/env bash
# pack.sh — создаёт чистый solution.zip с исходным кодом.
# Использует python zipfile, чтобы не зависеть от системного zip.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ZIP_NAME="solution.zip"
FILES=("main.py" "detectors.py" "store.py" "writer.py" "requirements.txt" "config.json")

# Удаляем старый архив, если есть
rm -f "$ZIP_NAME"

# Создаём архив через python
python - "$ZIP_NAME" "${FILES[@]}" <<'PYEOF'
import sys
import zipfile

zip_name = sys.argv[1]
files = sys.argv[2:]

with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zf:
    for f in files:
        zf.write(f, f)

print(f"Created {zip_name} with: {', '.join(files)}")
PYEOF

echo "Done."