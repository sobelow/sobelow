These fixtures were captured from the unmodified release tree at `4eb7d16`
(version 0.15.0), scanning `test/fixtures/apps/basic` with Elixir 1.20.4 / OTP 29.

`v0_15_0.json` stores JSON findings, fingerprint components exposed in the
Finding struct, every canonical check's SARIF rule ID, and SARIF results. SARIF
artifact URIs are normalized relative to the fixture app, matching the path
correction in this feature branch. Result fields are otherwise unchanged.

`v0_15_0.skips` contains the release's phash2 fingerprints. `legacy.skips`
contains its MD5 fingerprints. These are fixed inputs to regression tests,
independent of the new implementation's skip writer.

Do not refresh these fixtures just to make tests pass. An intentional contract
change needs an explicit compatibility decision and changelog entry. These
fixtures cover the representative basic app; they do not prove compatibility
for every possible Elixir AST or project layout.

The exact hash assertions and fixed skip inputs run on the captured Elixir 1.20
parser family. Older Elixir parsers attach different AST metadata, which was
already part of Sobelow's historical hashes. Output contracts and rule IDs are
checked on every matrix entry; existing skip round-trip tests also run on each
runtime. Add separately captured release fixtures to qualify fixed historical
hashes on other parser families rather than transforming the new output into
its own expected baseline.
