#!/bin/sh
# Build the labelled dataset on first start: from data/raw/manifest.yml when the OTRF data is
# mounted, otherwise the benign week plus the small test fixture so the dashboard has something to show.
set -e
if [ ! -f data/generated/events.parquet ]; then
  if [ -f data/raw/manifest.yml ]; then
    python -m data.build
  else
    echo "No data/raw/manifest.yml mounted; building the benign week + test fixture."
    python -m data.build --manifest tests/fixtures/otrf/manifest.yml
  fi
fi
exec "$@"
