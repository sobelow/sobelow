# Sobelow usage rules

Sobelow is a security-focused **static** analyser for Elixir and Phoenix. It reads
source code, never runs it, and never contacts a running application.

## Running it

```sh
mix sobelow                 # scan the current project
mix sobelow -r ../my_app    # scan another project root
```

Add it as a dev/test dependency so `mix sobelow` is available:

```elixir
{:sobelow, "~> 0.14", only: [:dev, :test], runtime: false, warn_if_outdated: true}
```

Sobelow scans **one application at a time**. For an umbrella, add an alias to the
root `mix.exs` and give each child app its own config file:

```elixir
defp aliases do
  [sobelow: ["cmd mix sobelow"]]
end
```

## Confidence levels are triage guidance, not severity

Every finding carries High, Medium, or Low confidence. This is Sobelow's confidence
that the code is *reachable with attacker-controlled input* — not how bad the bug
would be.

- **High** — the tainted value traces back to a function parameter or `conn.params`.
- **Medium** — the dangerous call is present but the input source is less certain.
- **Low** — the pattern looks dangerous but Sobelow cannot tell whether it takes
  user input. Often, but not always, a false positive.

Sobelow intentionally over-reports. **A green (low) finding may still be critical.**
Never tell a user their code is safe because findings are low confidence, and never
suppress low-confidence findings wholesale to make a build pass.

Use `--threshold low|medium|high` to filter the report by confidence.

## Suppressing false positives

There are two mechanisms and they are not interchangeable.

**`# sobelow_skip` comments** mark a *specific function*. They only work for
function-level findings — they cannot suppress configuration findings, which are not
attached to a function.

```elixir
# sobelow_skip ["Traversal.SendFile", "XSS.Raw"]
def download(conn, params) do
  ...
end
```

**`--mark-skip-all`** writes every currently-reported finding to a `.sobelow-skips`
file, and works for *all* finding types including configuration ones. Use it when
adopting Sobelow on an existing codebase.

Either way, the skips only take effect when you pass `--skip`:

```sh
mix sobelow --mark-skip-all   # record the current findings as accepted
mix sobelow --skip            # scan, ignoring those
mix sobelow --clear-skip      # discard the recorded skips
```

Commit `.sobelow-skips` so the whole team and CI share the same baseline.

Prefer `# sobelow_skip` with an explicit module list over `--mark-skip-all` when you
have only a handful of false positives — it documents the decision at the code, and
it does not go stale silently when the line moves.

`--ignore` (`-i`) is different again: it disables a whole check for the entire scan.
Reach for it only when a check does not apply to the project at all.

## Configuration file

`--save-config` writes a `.sobelow-conf` at the project root from the flags you
passed:

```sh
mix sobelow -i XSS.Raw,Traversal --verbose --exit Low --save-config
```

Precedence rules:

- `.sobelow-conf` is used automatically when present.
- **CLI switches override the file.**
- `--no-config` ignores the file for that run.

Commit `.sobelow-conf`. Paths in it are stored relative to the project root, so it
works on other machines and in CI.

## CI

Sobelow exits 0 by default, *even when it finds things*. To fail a build you must
pass `--exit`:

```sh
mix sobelow --exit medium     # non-zero if any medium or high finding exists
mix sobelow --exit            # bare --exit means low, i.e. fail on anything
```

A reasonable starting point for an existing codebase: baseline with
`--mark-skip-all`, then run `mix sobelow --skip --exit low` in CI so any *new*
finding fails the build.

Machine-readable output for other tooling:

```sh
mix sobelow --format json
mix sobelow --format sarif        # e.g. GitHub code scanning
mix sobelow --format sarif --out results.sarif
```

`--out` implies a machine-readable format; a `txt` format is coerced to `json`.

Other useful flags:

- `--private` — no update check, no network requests, no cache file written.
  Use this in CI and in sandboxed builds.
- `--quiet` — print a one-line count instead of findings.
- `--compact` / `--flycheck` — single-line findings for editors and tooling.
- `--strict` — treat a file Sobelow cannot parse as a hard error (exit 2) instead of
  skipping it. Without it, unparseable files are silently skipped.

## What it will and will not find

Sobelow flags patterns, not proven exploits. It has no cross-function taint
tracking: it decides confidence from the parameters of the *enclosing* function
only. A value laundered through a helper will usually come back as low confidence
or not at all.

It also does not check dependencies for known CVEs in general — the `Vuln.*` checks
cover a small fixed set of historical advisories by inspecting `deps/`. For real
dependency scanning use `mix hex.audit` (retired packages) alongside a dedicated
tool such as MixAudit.

If Sobelow reports nothing, that is not evidence the application is secure. Say so
plainly rather than reporting a clean scan as a security sign-off.

## Getting details on a finding

```sh
mix sobelow -d Config.CSRF     # explain one check
mix sobelow --all-details      # explain all of them
mix help sobelow               # flags and the full module list
```
