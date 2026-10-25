# Contributing

Thanks for considering a contribution to Pegasus-Sweep. This is a defensive
security tool and **triage** software — the bar is correctness and honesty
about limits, not feature breadth.

## Ground rules

1. **Never overstate detection.** A clean result must never be presented as
   proof of non-infection. If a change would make a reviewer believe the tool
   "confirms" a device is clean, it is out of scope.
2. **No covert or unconsented scanning.** This project only scans devices the
   operator owns or is authorized to assess. Do not add remote, silent, or
   persistence-in-target behavior.
3. **Indicators stay in the oracle.** Add/refresh `indicators/pegasus_iocs.yaml`
   — never hard-code new signatures into matcher code. Every finding must stay
   provenance-tagged.
4. **Match the verification gates.** New code must pass the self-test below and
   import cleanly; new HTTP behavior should be covered in an ad-hoc check.

## Development setup

```bash
python -m venv .venv
. .venv/Scripts/activate        # Windows (git-bash: source .venv/Scripts/activate)
pip install -r requirements.txt
```

The web dashboard also wants `psutil` (already in requirements) and, for phone
checks, Amnesty `mvt` (`pip install mvt`) on the machine that owns the device.

## Running checks

```bash
# compile all modules
python -m compileall pegasus_sweep agent/agent_desktop.py

# unit-style self-test (no phone / MVT required)
python -m pegasus_sweep.tests.test_detection

# manual web smoke (then hit http://127.0.0.1:8097)
python -m pegasus_sweep.web.app
```

CI runs the same self-test on every push/PR (`.github/workflows/ci.yml`).

## Adding indicators

Append to `indicators/pegasus_iocs.yaml` under the right section, preserving
the schema and, ideally, citing a source in the `meta` block. Then re-run the
self-test. Keep additions **documented**; the oracle ships as a seed set and
should not be silently polluted with unverifiable mass data.

## Android agent

`android_agent/` needs an Android SDK toolchain (AGP 8.5 + JDK 17) which CI
cannot exercise here. If you change it, at minimum ensure the Kotlin compiles
and the manifest references only resources that exist. Document any behavior
change in `android_agent/README.md`.

## Documentation

Substantive behavior changes must update the relevant docs in `docs/`
(`api.md` for endpoints, `architecture.md` for component/data-flow changes,
`methodology.md` for any claim about detection limits).

## Pull request checklist

- [ ] `python -m pegasus_sweep.tests.test_detection` passes
- [ ] `python -m compileall pegasus_sweep agent/agent_desktop.py` passes
- [ ] No secrets, runtime DBs (`data/`, `uploads/`, `reports/`), or logs added
- [ ] Docs updated if endpoints/components/methodology changed
- [ ] New indicators added to the oracle, not matcher code