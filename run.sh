#!/usr/bin/env bash
# Launcher for the Cubic Castles live bot. Just run:  ./run.sh
#   - holds the fixed flags so you don't retype them
#   - anything you add on the line is passed through, e.g.:  ./run.sh --crawl-delay 5
# "$(dirname "$0")" = this file's folder, so it works from any directory.
HERE="$(cd "$(dirname "$0")" && pwd)"
"$HERE/.venv/bin/python" "$HERE/stage2/cc_client.py" live \
  --i-accept-live-risk \
  --control-port 8777 \
  --control-host 0.0.0.0 \
  --control-token pickAsecret \
  "$@"
