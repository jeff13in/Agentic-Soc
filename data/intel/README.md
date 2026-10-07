Recorded threat-intel responses.

- `recorded.json` (optional, committed): responses recorded from live lookups for the IPs, hashes and
  domains in the OTRF datasets, shaped `{"ip": {...}, "hash": {...}, "domain": {...}}`. `python -m data.build`
  merges it into `data/generated/mock_intel.json`, which evals read in `mock` mode.
- `live_cache.json` (git-ignored): written by `SOC_INTEL_MODE=cache`. Review it and copy entries into
  `recorded.json` to make them part of the reproducible eval set.
