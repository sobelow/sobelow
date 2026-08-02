# AGENTS.md

Guidance for AI coding agents (and new contributors) working **on** Sobelow.

If you are looking for how to *use* Sobelow in your own project, read
[`usage-rules.md`](usage-rules.md) instead.

## What this project is

Sobelow is a security-focused static analyser for Elixir and Phoenix. It parses
source to AST with `Code.string_to_quoted/2`, walks it with `Macro.prewalk/3`
looking for known-dangerous shapes, and reports findings with a confidence level.

It ships two entry points that share all logic:

- `mix sobelow` — the Mix task (`lib/mix/tasks/sobelow.ex`)
- an escript — same module, via `main/1`

## Layout

```
lib/
  mix/tasks/sobelow.ex      CLI: option parsing, .sobelow-conf merge, dispatch
  sobelow.ex                Pipeline: file discovery, scan orchestration, skips,
                            version check, module-name registry
  sobelow/
    parse.ex                AST helpers shared by every check (the workhorse)
    print.ex                Human-readable output and confidence grading
    finding.ex              %Finding{} struct, fingerprints, `use Sobelow.Finding`
    finding_log.ex          Findings collector; json/1 and sarif/1 renderers
    meta_log.ex             Template state
    fingerprint.ex          Skip-list state
    config.ex               Config-file category + config parsing helpers
    <category>.ex           Category module (XSS, SQL, Traversal, RCE, ...)
    <category>/<check>.ex   Individual check
test/
  support/scan_case.ex      End-to-end scan harness
  fixtures/apps/            Fixture applications scanned end to end
  fixtures/<check>/         Single-file fixtures for unit tests
  e2e/                      End-to-end tests
```

## Build and check

```sh
mix deps.get
mix test                # unit + e2e
mix test.all            # hex.audit, format, warnings-as-errors, unused deps, credo
mix coveralls           # coverage report
```

CI runs the matrix in `.github/workflows/elixir.yml`. `mix credo --all --strict`
runs on **every** matrix entry and must be clean; formatting and
`--warnings-as-errors` are enforced on the newest Elixir only.

The minimum supported Elixir is declared in `mix.exs` (`elixir: "~> 1.12"`). Do not
use syntax or stdlib functions newer than that floor without also raising it — that
is a breaking change for downstream users and belongs in its own PR.

## Adding a check

A check is a module that sets two attributes, calls `use Sobelow.Finding`, and
implements `run/N`. `lib/sobelow/traversal/send_file.ex` is a representative example:

```elixir
defmodule Sobelow.Traversal.SendFile do
  @moduledoc """
  # Directory Traversal in `send_file`

  Prose shown by `mix sobelow -d Traversal.SendFile`, and used verbatim as the
  SARIF rule help text.

  Send File checks can be ignored with the following command:

      $ mix sobelow -i Traversal.SendFile
  """
  @uid 21
  @finding_type "Traversal.SendFile: Directory Traversal in `send_file`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  ## send_file(conn, status, file, offset \\ 0, length \\ :all)
  def parse_def(fun) do
    # index 2 == the `file` argument
    Parse.get_fun_vars_and_meta(fun, 2, :send_file, :Conn)
  end
end
```

`use Sobelow.Finding` aliases `Finding`, `Parse`, `Print`, and `Utils` for you, and
defines `details/0`, `id/0`, and `rule/0`.

**The arity of `run/N` is set by the parent category, not by convention.** Each
category module defines `get_vulns/4` and decides what to pass along —
`Sobelow.Traversal` calls `run/2`, `Sobelow.XSS` calls `run/4`, and the
config-file categories call `run/1` or `run/2` with paths instead of an AST. Match
the sibling checks in the category you are adding to.

The index passed to `Parse.get_fun_vars_and_meta/3,4` is the zero-based position of
the tainted argument in the function being flagged. Note the comment above
`parse_def/1` recording the signature — keep that habit, it is the only place the
index is explained.

**`@uid` must be unique across the whole project.** It becomes the SARIF rule id
(`SBLW` + zero-padded uid). Check existing uids before picking one:

```sh
grep -rh "@uid" lib/ | sort -n -k2
```

**`@finding_type` must be `"<Module.Check>: <description>"`.** The `:`-split is
load-bearing — `Sobelow.Finding.rule/0` uses it to build the SARIF rule name, and
`FindingLog.format_sarif/1` uses the prefix to look the module back up.

### Register the check in all three places

Missing any one of these fails silently:

1. `@submodules` in the parent category module (e.g. `lib/sobelow/traversal.ex`) —
   without this the check never runs.
2. `Sobelow.get_mod/1` in `lib/sobelow.ex` — without this `--ignore`,
   `# sobelow_skip`, and the SARIF `ruleId` all silently stop working for it.
3. The "Supported modules" list in the `@moduledoc` of
   `lib/mix/tasks/sobelow.ex` — this is what `mix help sobelow` prints.

### Output formats

Do not call `IO.puts` from a check. Route findings through `Print.add_finding/1`,
which dispatches on `Sobelow.format()`. If a check needs extra fields beyond
type/file/line/variable, follow the pattern in `Sobelow.Config.Secrets.add_finding/5`:
a `case Sobelow.format()` with a branch per format, using
`Print.print_custom_finding_metadata/2` for `"txt"`.

Every branch must be handled: `"json"`, `"txt"`, `"compact"`, `"flycheck"`, and a
catch-all `_` that only logs. `"sarif"` is rendered from the log, not per-finding —
`Sobelow.format/0` maps it to `"json"`.

### Confidence

`Print.get_sev/2,3` grades a finding by whether the tainted variable is one of the
enclosing function's parameters (or `conn.params`), i.e. plausibly user-controlled.
`Finding.multi_from_def/3` calls it with the confidence you passed to
`Finding.init/3`:

- `nil` or `false` — grade it: `:high` if user-controlled, `:medium` otherwise
- an explicit atom (`:low`) — pin it, skipping the grading

The common idiom is to pin `:low` outside controllers and let it grade inside them.

Sobelow deliberately over-reports; when unsure, emit a low-confidence finding
rather than nothing.

## Robustness rules

These are the invariants the crash-class bug fixes established. Preserve them.

- **A single bad file must never abort a scan.** `Parse.ast/1` returns `{}` for
  unparseable sources, and `Parse.get_meta_template_funs/1` returns empty metadata
  for unparseable templates — unless `--strict` is set, which is the only mode
  allowed to `System.halt/1` on a parse failure.
- **Never `System.halt/1` from a check.** Only the CLI layer and `--strict` may halt.
- **Never fail a scan over auxiliary state.** A corrupt version-check cache, an
  unwritable `~/.sobelow`, or a missing `deps/` directory must degrade quietly.
  A security tool that exits 0 without scanning is worse than one that reports
  nothing at all.
- **Prefer total functions over pattern matches that assume success.** Several past
  bugs were `{a, b} = some_call()` where `some_call()` had a scalar fallback.

## Fingerprints and skips

`Finding.fingerprint/1` is `:erlang.phash2([type, vuln_source, filename, vuln_line_no])`.
It is what `.sobelow-skips` entries match on.

**Changing any component changes the fingerprint**, which silently invalidates
users' committed skip files and resurfaces findings they had triaged away. If a
change moves reported line numbers, say so explicitly in the CHANGELOG. There is a
`legacy_fingerprint` (md5) kept for backwards compatibility with older skip files —
follow that precedent rather than breaking people.

## Tests

- End-to-end: `use Sobelow.ScanCase`, then `scan("<fixture app>")` returns the
  decoded JSON report. Helpers: `findings/1`, `finding_modules/1`,
  `findings_for/2`, `scan_io/2` for raw stdout/stderr, `temp_fixture_file/3` for
  files that must not be committed in a broken state.
- These tests must be `async: false` — the scan pipeline uses named processes and
  application env.
- Unit: single-file fixtures under `test/fixtures/<check>/` exercising the check's
  parsing helpers directly. See `test/config/csrf_test.exs`.

`mix format` covers `test/**`, so a fixture that is *meant* to be syntactically
invalid must be written at runtime with `temp_fixture_file/3`, not committed.

Do not name a fixture `*_test.exs` — ExUnit will load it as a test file.

## Conventions

- Run `mix format` before committing; CI enforces it.
- Internal modules are `@moduledoc false`. A check's `@moduledoc` is user-facing
  documentation printed by `-d` — write it for a developer triaging a finding.
- Test-only public functions get `@doc false`.
- Keep the public API additive. Sobelow is depended on widely enough that renaming
  or removing a check, a CLI flag, or a finding type is a breaking change.
