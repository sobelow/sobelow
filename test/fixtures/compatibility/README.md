The release fixtures were captured from the unmodified release tree at `4eb7d16`
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

`v0_15_0_columns.json` stores SARIF columns captured independently from the same
unmodified release on Elixir 1.12.3, 1.13.4, 1.14.5 (OTP 24), and 1.15.8 (OTP 26).
Elixir 1.12 places qualified-call columns one character earlier; EEx before 1.16
does not retain expression columns and SARIF uses its existing column-1 fallback.
The compatibility test uses these fixed columns on the corresponding parser
families and still compares every remaining SARIF result field. This preserves
historical runtime behaviour without changing scan output or fingerprints.

`public_api.json` records every public function and arity on `Sobelow` and
`Sobelow.Parse` at `97019bc`, before extracting the internal scan and parsing
modules. It includes traversal callbacks and generated default arities.
The compatibility test requires these entry points to remain callable; adding
functions is allowed. Existing behavioral tests exercise them through the
facades, and the benchmark compares complete findings and output separately.
