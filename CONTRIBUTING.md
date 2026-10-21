# Contributing to pcaplens

Thanks for helping. Small, focused PRs are easiest to review.

## Development setup

```bash
git clone https://github.com/GameMaster007/pcaplens.git
cd pcaplens
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check src tests scripts
```

## Guidelines

1. **Authorised data only** — never commit real customer PCAPs or credentials.
2. Prefer **synthetic** traffic via `pcaplens.synth` / `pcaplens gen-sample`.
3. New detections need: a threshold constant (documented), a MITRE mapping, a
   pytest that fires on a synthetic PCAP, and a clean-capture check that still
   passes.
4. Keep the CLI stable; add flags rather than renaming commands.
5. Run `ruff check` and `pytest` before opening a PR.

## Pull requests

- Fork, branch from `main`, open a PR with a short “why”.
- Link related issues.
- One logical change per PR when practical.

## Code of conduct

Be respectful. Harassment or bad-faith security misuse of this tool is not
welcome.
