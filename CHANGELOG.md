# Changelog

## Unreleased

  * Bug fixes
    * `XSS.Raw` no longer reports calls to a benign local `raw` helper with the matching
      arity, including defaults, guards, pipes, captures, and inline HEEx. Local
      definitions stay within their module; qualified Phoenix calls and
      implicitly imported template helpers retain detection. Helpers returning
      dynamic `{:safe, value}` output or wrapping another `raw` call retain
      their caller's original findings, locations, and fingerprints. (#44)
    * `XSS.SendResp` now recognizes `put_resp_header(conn, "content-type", type)`
      on the response connection, including piped, aliased, nested, and assigned
      calls. HTML, SVG, malformed, and unknown types still report; other XML
      and PDF document types retain low-confidence findings. Discarded, later,
      unrelated, locally shadowed, or ambiguously imported setters cannot
      suppress findings. Known unrelated response headers retain the connection's
      content type, and MIME parameters do not change its classification. (#45)
    * `XSS.Raw` now respects explicit imports of unrelated `raw` helpers. Unknown
      raw macros and delegates retain detection. Older inline lexical contexts
      without local-signature metadata remain supported.
    * Invalid project roots, roots with no scannable source files, invalid scan
      options, and unwritable output files now fail with actionable errors.
    * Repeated scans in the same VM now start with fresh findings, template, and
      skip state. Malformed sources and templates are skipped with a warning in
      non-strict mode, and unreadable files are skipped with a warning.
    * Dynamic socket options, literal statements in router pipelines, and access
      on a literal keyword list no longer abort scans. Unknown socket options
      produce low-confidence findings.
    * `XSS.SendResp` now follows the connection passed to each response and its
      content type before that sink. Later or discarded setters cannot suppress
      an earlier finding, and rebindings in branches, patterns, callbacks,
      generators, and call arguments cannot borrow another connection's content
      type. Unchanged bindings, pins, guards, and explicit setters retain their
      existing handling.
    * HTTPS and HSTS checks now use effective settings for the scanned application
      and each endpoint, including ordered overrides and nested keyword merges.
      One endpoint cannot satisfy another's settings. Dynamic and conditional
      settings produce low-confidence findings. Empty CSP policies are reported.
    * Enabled sockets now inherit endpoint origin settings from base, production,
      and runtime configuration, including `socket/2` and `websocket: true`.
      Explicit socket overrides retain precedence, and
      disabled WebSockets remain excluded. Defaults are isolated to each endpoint
      module. Origin allowlists and `:conn` are recognized; an enabled CSRF check
      lowers confidence when origin checks are disabled.
    * HEEx comments and script/style text no longer change brace-interpolation
      scope or introduce findings from literal markup. The
      `phx-no-curly-interpolation` directive is recognized as an attribute name;
      the same text inside another attribute's value cannot suppress findings.
      Inline columns account for sigil prefixes and heredoc indentation.
    * Module-local `use` and `import` declarations now apply only to their own
      module. Named captures and inline HEEx retain lexical aliases and import
      selections, including renamed aliases and imported arity restrictions.
    * Lockfile dependency advisories now require the Hex package name to match
      the checked dependency, preventing false advisories for package aliases.
      Missing or nonliteral versions no longer abort scans.
    * Explicit router paths now resolve relative to `--root`. SARIF locations
      are relative to the scan root, or use file URIs for external files. Reserved
      filename characters, including `#`, `?`, `%`, and `:`, are percent-encoded.
      JSON filenames and skip fingerprints are unchanged.
    * SARIF's `Vuln.CookieRCE` rule name now matches its existing result type and
      rule ID. Unknown finding types receive a null rule ID instead of raising.
      `Config.CSRFRoute` is now listed in `mix help sobelow`.
    * Optional version checks now verify TLS certificates and hostnames when a
      trusted CA store is available, and tolerate malformed responses, cache,
      filesystem, and network failures. OTP 24 skips the notification because
      it has no built-in CA-store API.
  * Enhancements
    * Added a `github` output format for GitHub Actions workflow annotations,
      with confidence levels and repository-relative finding locations.
    * Added detection of raw output in HEEx files and inline `~H` sigils,
      including body and attribute expressions, legacy EEx, qualified and piped
      `Phoenix.HTML.raw` calls, nested sigils, and Elixir comments. Controller
      renders are correlated with embedded `*_html` templates. Brace
      interpolation is disabled in script/style bodies and regions marked with
      `phx-no-curly-interpolation`. Invalid expressions warn and are skipped, or
      exit 2 under `--strict`.
    * Added static resolution of renamed and grouped aliases, nested module
      inheritance, function-local imports, and `only`/`except` arity selections.
      Confidence grading follows direct local aliases before a sink. Calls
      retain their original ASTs, and implicit Phoenix controller imports retain
      their historical detection.
    * The existing fixed set of `Vuln.*` dependency advisories can now read literal
      Hex versions from `mix.lock` when `deps/` is unavailable, without evaluating
      project code.
    * Added `--include-mix-tasks` and `--include-scripts` to opt into additional
      source paths, and `--summary` to print file counts on stderr. SARIF now
      includes invocation warnings and uses the published OASIS schema URL.
    * `.sobelow-conf` saves and sorted skip rewrites are now atomic, preserve Unix
      permissions, and follow symlinks. Unreadable existing skip files are
      preserved and produce an actionable error. `--legacy-skips` retains the
      existing append behavior.
    * Improved scan speed with shared function call, pipe, parameter, and
      confidence analysis; incremental HEEx delimiter parsing; combined
      file/module metadata extraction; bounded, ordered file preparation; and
      smaller lexical contexts with compatible lookup paths on older OTP.
    * Batched finding and fingerprint updates, retaining each function source
      once per batch. Quiet output and exit status use confidence counts, and
      repeated reports reuse sorted results. Scan settings, enabled checks,
      paths, skip lookups, and relevant template snapshots are reused, with
      per-worker cache counters to avoid contention. Source, AST, lockfile, and
      dependency-version caches are released when the scan finishes or fails.
      Existing public finding-log results and output formats are preserved.
  * Testing
    * Expanded regression coverage for output and verbose highlighting, advisory
      boundaries, configuration uncertainty, atomic writes, source edge cases,
      and scan/lexical context restoration. Added failing regressions and safe
      controls for Copilot and adversarial review findings.
    * Added release 0.15.0 fixtures for JSON/SARIF output, rule IDs, fingerprints,
      and both historical skip formats. Exact fingerprint assertions run on the
      captured parser family; output/rule contracts and generated skip round
      trips run across the supported matrix. Independent release column captures
      qualify older parsers, and highlighting follows each runtime's printer.
    * Added compatibility coverage for all 70 pre-extraction public function and
      arity pairs on `Sobelow` and `Sobelow.Parse`, including traversal callbacks
      and default arities.
    * Expanded benchmarks to seven workloads and quiet/JSON/SARIF output, with
      complete finding and output comparisons, reduction counts, and separate
      sampled VM memory. Methodology, measurements, and limits are documented in
      `bench/README.md`; the benchmark entry point is `bench/scan.exs`.
    * Raised line coverage from 85.2% to 98.5%, with a 98% gate on the newest CI
      runtime. Coverage excludes only the test harness, documentation-only legacy
      module, and developer diff helper. Fixtures are ignored by test discovery.
    * Isolated named processes and application configuration in legacy tests to
      prevent order-dependent failures on older Elixir versions. Version-check
      cache, response, and TLS-option tests make no network requests.
    * CI builds and smoke-tests the escript on every supported Elixir/OTP
      combination, including exit codes; strict Credo runs on every entry.
  * Misc
    * Split scan discovery, execution, skip-file persistence, and version checks
      into focused internal modules. Shared AST helpers now live in source,
      metadata, calls, variables, and template modules, with the existing
      `Sobelow` and `Sobelow.Parse` entry points preserved.
    * Consolidated duplicate matchers and worker setup, reused relative-path
      handling, and shortened stale comments. Updated contributor and usage
      guidance to document the new module boundaries and scan options.

### Upgrade notes

  * **Newly supported unsafe patterns can produce additional findings.** HEEx,
    inline templates, lexical resolution, response rebindings, and configuration
    fixes can reveal previously missed sinks. Corrected lockfile package matching
    can remove false dependency advisories.
  * **Invalid invocations and failed output writes now fail explicitly.** Check
    project roots, scan options, and output permissions if an invocation previously
    exited successfully without scanning or writing its report.
  * Existing check names, finding types, CLI flags, JSON finding fields, original
    ASTs, existing finding locations, and current/legacy fingerprint calculations
    are preserved. SARIF artifact paths are corrected as described above. The
    minimum supported Elixir version remains `~> 1.12`.

## v0.15.0
  * Bug fixes
    * `Config.Secrets` no longer crashes the scan when a secret is written as
      anything other than a plain double-quoted string. Heredoc values and values
      containing escaped quotes previously raised a `MatchError` and aborted the
      entire run. These secrets are now reported, using the line of the enclosing
      `config` call.
    * A corrupt or unreadable version-check cache file no longer aborts the scan.
      Sobelow previously printed "This does not appear to be a Phoenix application"
      and exited **0** — a CI gate could pass having scanned nothing.
    * `--strict` now reports syntax errors instead of raising. It has been broken
      since Elixir 1.13 changed the error shape returned by
      `Code.string_to_quoted/2`. Errors are now reported as `file:line:column:`.
    * A template that cannot be parsed is now skipped (or reported under
      `--strict`) rather than aborting the scan with an `EEx.SyntaxError`. The
      error now names the offending template instead of `nofile`.
    * A malformed `.sobelow-conf` now produces an actionable message instead of a
      raw `MatchError` stacktrace. This mattered more since v0.14.1 began reading
      the file automatically.
    * An empty, whitespace-only, or comment-only `.sobelow-conf` is now read as
      no options rather than aborting the scan. Such a file parses to an empty
      block instead of a keyword list, so it originally crashed with a
      `FunctionClauseError` and then, once that was fixed, exited 1 with a
      configuration error. Since the file is read automatically, a stray
      `touch .sobelow-conf` or a truncated write was enough to break every scan
      in a project. Contents that cannot be interpreted are still an error.
    * `--save-config` now stores `ignore_files` relative to the project root.
      Absolute paths were previously baked into `.sobelow-conf`, breaking the
      committed file on every other machine and in CI.
    * `Config.Secrets` now reports the line of the secret itself when a `config`
      call spans multiple lines. The line search compared a tuple against an
      integer, so it never worked as intended.
    * An unwritable `~/.sobelow` no longer fails a scan.
    * Fixed a string-interpolation typo that rendered dot-access variables as
      `conn.${atom_to_string(field)}`.
    * `.sobelow-conf` keys are now genuinely sorted alphabetically.
    * A `.sobelow-conf` can no longer stop Sobelow from scanning. `--save-config`
      wrote `version` into every file it generated, so
      `mix sobelow --version --save-config` produced a committed file that made
      every later run print the version and **exit 0** — a CI gate reading that
      as a clean scan. `version`, `details`, `all-details`, `save-config`, and
      `diff` choose what Sobelow does rather than configure a scan, and are now
      accepted on the command line only. One in the file is ignored, with a
      warning when it would have changed anything. `version` is no longer
      written to the file in the first place.
    * `# sobelow_skip` comments are no longer thrown away over whitespace. The
      pattern demanded exactly one space after the `#` and exactly one before
      the list, so `# sobelow_skip["XSS.Raw"]`, `#  sobelow_skip ["XSS.Raw"]`,
      and `# sobelow_skip [ "XSS.Raw" ]` were all ignored — silently, and
      indistinguishably from a skip that had simply not applied. Spacing around
      the marker, inside the list, and around commas is now irrelevant.
    * `SQL.Query` no longer reports a project's own `query/1` as SQL injection.
      An unqualified `query`/`query!` call was matched regardless of what it
      referred to, so every call to a local function that happened to carry one
      of those very ordinary names produced a finding. The unqualified form is
      now only considered in a file that has `import Ecto.Adapters.SQL` or
      `use Ecto.Repo` — the two ways the bare name can actually reach Ecto.
      Qualified calls, such as `Repo.query/1` and `Ecto.Adapters.SQL.query/3`,
      are unaffected.
  * Enhancements
    * Added `--no-router`, for scanning a project that has no Phoenix router.
      Sobelow warned that it could not find one and offered no way to silence it,
      which was noise for plain Elixir libraries. It is shorthand for
      `--router :none`, which can also be set in `.sobelow-conf` as
      `router: :none`. The router-dependent checks are skipped either way.
    * `.sobelow-skips` is now written in sorted order, so regenerating it after
      fixing or adding a finding produces a small diff instead of reshuffling the
      file. Entries sort by type, file, and line number — numerically, so line 10
      follows line 9 rather than line 1. The whole file is sorted, not just the
      newly added entries, so the ordering holds however many times it is
      regenerated. Comments and pre-v0.14 bare-fingerprint lines are preserved.
      Pass `--legacy-skips` for the previous append-only behaviour, which never
      rewrites lines it did not add.
    * `# sobelow_skip` comments now work on Phoenix router pipelines, not just
      functions. This makes `Config.CSRF`, `Config.Headers`, and `Config.CSP`
      suppressible per pipeline instead of only via `--mark-skip-all`, so an API
      pipeline that legitimately has no `:protect_from_forgery` can be annotated
      in place. Listing the parent `Config` module skips every Config check on
      that pipeline. As with function-level skips, this only takes effect under
      `--skip`.
    * A `# sobelow_skip` comment that cannot be read now warns on stderr, naming
      the file and line, instead of being dropped without a word. Single quotes
      and a list broken across several comment lines are still not accepted, but
      they now say so rather than leaving you to wonder why the finding came
      back.
    * `--private` now skips the version check entirely rather than still writing
      the cache file. It makes no network requests and touches no files outside
      the scanned project.
    * `SOBELOW_HOME` is now documented, and is treated as the *directory* holding
      the version-check cache.
    * Added `usage-rules.md`, following the `usage_rules` convention, so projects
      using AI coding assistants can pull Sobelow's guidance into their agent's
      context with `mix usage_rules.sync`. It is shipped in the Hex package.
    * Added `AGENTS.md` documenting the checker-module contract for contributors.
    * Added support for Elixir v1.20.x.
  * Testing
    * Added an end-to-end test harness (`Sobelow.ScanCase`) that runs full scans
      against fixture applications under `test/fixtures/apps`, plus regression
      coverage for every bug above. Line coverage went from 29% to 67%.
    * Added coverage for CLI option parsing, `.sobelow-conf` precedence, `--exit`
      and `--threshold` mapping, and the `json`/`sarif`/`quiet`/`txt` renderers.
    * Added end-to-end coverage for pipeline-level `# sobelow_skip` comments, and
      unit coverage for how skips associate with pipelines in the AST.
    * `Sobelow.ScanCase.temp_fixture_file/3` now restores a committed fixture's
      original contents instead of deleting the file, so a test can vary a
      checked-in fixture without destroying it.
  * Misc
    * Replaced the deprecated `:preferred_cli_env` project key with `def cli`.
    * Bumped `credo` to `~> 1.7.19`; 1.7.12 crashed on Elixir 1.20.
    * Removed a dead Elixir 1.5 version guard and fixed an always-true conditional
      in the SARIF renderer.

### Upgrade notes

  * **`Config.Secrets` line numbers may change** for `config` calls that span
    multiple lines, and for files where the same secret value appears more than
    once. Finding fingerprints include the line number, so any affected
    `.sobelow-skips` entries will stop matching and those findings will resurface.
    Re-run `mix sobelow --mark-skip-all` if you rely on a committed skip file.
  * **Secrets that previously crashed the scan are now reported.** If a heredoc or
    escaped-quote secret exists in your config, you will see new findings where the
    scan previously failed outright.
  * **`SOBELOW_HOME` semantics changed** from "path to the cache file" to "directory
    holding the cache file". The previous behaviour raised a `MatchError` for the
    natural usage, so this is unlikely to affect anyone.

## v0.14.1
  * Enhancements
    * Implicitly use `.sobelow-conf` if detected in the root directory rather than
      require `--config` switch. The `--no-config` switch is still supported to
      prevent any settings from being read in from the file if needed.
    * Added guidance for `warn_if_outdated` option in mix deps
    * Added support for Elixir v1.19.x
  * Bug fixes
    * Handled extra config options for app releases in mix.exs
    * Properly handle the use of CLI switches and config file settings in the same run.
      These would previously clobber each other in unapparent ways leading to
      confusing behavior. CLI switch take precedence.
    * `.sobelow-conf` now sorted alphabetically
    * Fix edwarning from zero argument functions
    * Fixed broken skip funcationality
    * Fixed broken GitHub Actions CI
  * Misc
    * Typo fix

## v0.14.0
  * Removed
    * Support for minimum Elixir versions 1.7 - 1.11 (**POTENTIALLY BREAKING** - only applies if you relied on Elixir 1.7 through 1.11, 1.12+ is still supported)
  * Enhancements
    * Added support for multiple variations of `SQL.query()`
    * Added support for `System.shell' command introduced in Elixir v1.12
    * Ignore runtime config during `Config.HSTS`
    * Updated developer dependencies (`ex_doc` & `credo`)
  * Bug fixes
    * Fixed `is_endpoint?` error in main
    * Fixed findings normalization bug
    * Fixed truncation error
  * Misc
    * GitHub Actions test matrix updated (hence the large drop in support for old Elixir versions)
    * Addressed compiler warnings from Elixir v1.18.x
    * Moved from `master` branch to `main`

## v0.13.0
  * Removed
    * Support for minimum Elixir versions 1.5 & 1.6 (**POTENTIALLY BREAKING** - only applies if you relied on Elixir 1.5 or 1.6, 1.7+ is still supported)
  * Enhancements
    * Fixed all `credo` warnings
    * Implemented all `credo` "Code Readability" adjustments
    * Took advantage of _some_ `credo` refactoring opportunities
    * Added (sub)module documentation that was missing for some vulnerabilities and unified presentation of others
  * Bug fixes
    * Fixed `--details` / `-d` not displaying correct information
    * Fixed incompatibility issue with Elixir 1.15
  * Misc
    * Added `mix credo --strict` to project
    * Improvements to GitHub CI
      * Hex Audit
      * Compiler Warnings as Errors
      * Checks Formatting
    * Added helper `mix test.all` alias

## v0.12.2
  * Bug fixes
    * Removed `:castore` and introduced `:verify_none` to quiet warning and unblock escript usage, see [#133](https://github.com/nccgroup/sobelow/issues/133) for more context on why this is necessary

## v0.12.1
  * Bug fixes
    * Lowered required version of `:castore` to remove upgrade path issues
    * Reconfigured `:verify_peer` to _actually_ use CAStore and remove warning

## v0.12.0
  * Removed
    * Support for minimum Elixir version 1.4 (**POTENTIALLY BREAKING** - only applies if you relied on Elixir 1.4, 1.5+ is still supported)
  * Enhancements
    * Adds support for HEEx to XSS.Raw
    * Adds `--version` CLI flag
    * README Improvements
      * Umbrella App usage
      * Clearer installation process
      * Layout changes
    * Updated dependencies
  * Bug fixes
    * Adds to_string() to exit_on
    * Sets SSL opt verify_peer in version check
    * Reworks `-v, --verbose` printing to not use the now deprecated `Macro.to_string/2`
  * Misc
    * Allows atom values for threshold in config file
    * Uses SPDX ID for licenses in mixfile
    * Fixed typo

## v0.11.2
  * Enhancements
    * Simplify `--flycheck` output to align with expected format

## v0.11.1
  * Enhancements
    * Sarif output with `--out` flag
    * `--strict` flag, which throws compilation errors instead of suppressing them.

## v0.11.0
  * Enhancements
    * Sarif output for GitHub integration
    * `--flycheck` flag, which reverses output of `--compact`
  * Bug fixes
    * Non-compiling files now return an empty syntax tree instead of
    causing Sobelow errors.
    * Command Injection finding description are properly formatted
  * Misc
    * If you use Sobelow as a standalone utility (i.e. not as part of
    a Phoenix application), you now need to install as an escript with
    `mix escript.install hex sobelow`.
    * Custom JSON serialization replaced with Jason.

## v0.10.6
  * Bug fixes
    * Handle nil `config` case

## v0.10.5
  * Misc
    * Update code to clean up deprecation warnings

## v0.10.4
  * Enhancements
    * Sobelow is now smarter about cross-site websocket hijacking
    * Update URL for CSRF description

## v0.10.3
  * Bug fixes
    * Fix directory structure issue in umbrella applications
    * Handle function capture edge cases

## v0.10.2
  * Bug fixes
    * Fix a format error in JSON output encoding

## v0.10.1
  * Bug fixes
    * Sobelow will use ".sobelow-skips" instead of ".sobelow" in your root directory for `--mark-skip-all`

## v0.10.0
  * Enhancements
    * Sobelow now uses "~/.sobelow/sobelow-vsn-check" for update checks
    * The ".sobelow" file in your project root is for `--mark-skip-all` only

## v0.9.3
  * Enhancements
    * Improved checks for all aliased functions

  * Bug Fixes
    * JSON output for Raw findings is now properly normalized
    * `send_download` correctly flags aliased function calls
    * `send_download` now correctly flags piped functions

## v0.9.2
  * Bug Fixes
    * Fix error that resulted from redefining imported functions

## v0.9.1
  * Bug Fixes
    * Revert umbrella app recursion

## v0.9.0
  * Enhancements
    * Add `--mark-skip-all` and `--clear-skip` flags
    * New CSRF via action reuse checks
    * Sobelow can now be run in umbrella apps

  * Bug Fixes
    * Fix an error when printing some kinds of variables

## v0.8.0
  * Enhancements
    * Improve output consistency
        * All JSON findings contain `type`, `file`, and `line` keys
        * "Line" output now refers directly to the vulnerable line
        * Default output headers have been normalized

    **Note:** If you depend on the structure of the output, this
    may be a breaking change. More information can be found at
    [https://sobelow.io](https://sobelow.io).

## v0.7.8
  * Enhancements
    * Add `--threshold` flag
    * Add module names to finding output

  * Deprecations
    * File/Path check has been deprecated

  * Bug Fixes
    * Fix inaccurate CSRF details

## v0.7.7
  * Enhancements
    * Add check for insecure websocket settings

  * Bug Fixes
    * Accept module attributes for application name

## v0.7.6

  * Bug Fixes
    * Fix issue that suppressed output options when config files were in use

## v0.7.5

  * Misc
    * Sobelow will now only halt when `--exit` flag is used

## v0.7.4

  * Bug Fixes
    * Log hardcoded secrets for txt output

## v0.7.3

  * Misc
    * Tweaks to `--out` flag.

## v0.7.2

  * Enhancements
    * Add router path to config findings
    * Add `--out` flag for writing to file

## v0.7.1

  * Enhancements
    * Improved handling of JSON format
    * Additional checks for File functions

## v0.7.0

  * Enhancements
    * Improved handling of vulnerabilities within templates.

  * Bug Fixes
    * Sobelow no longer incorrectly flags :binary `send_download` functions.

## v0.6.9

  * Enhancements
    * Improve template parsing and validation.
    * Support multiple routers, and improve route discovery.

  * Misc.
    * Update language for missing directory.

## v0.6.8

  * Bug Fixes
    * Fix bug in the handling of certain piped functions.
    * Revert not/in update that broke Elixir 1.4 compatibility.

## v0.6.7

  * Enhancements
    * Remove banner print from JSON format.

  * Bug Fixes
    * Fix error that occurred with certain function names in JSON format.

## v0.6.6

  * Enhancements
    * Add check for directory traversal via `send_download`
    * Add check for missing Content-Security-Policy
    * Check additional XSS vectors

## v0.6.5

  * Bug Fixes
    * Allow RCE module to be appropriately ignored.

## v0.6.4

  * Enhancements
    * Set timeout for version check.

## v0.6.3

  * Enhancements
    * Add RCE module to check for code execution via `Code` and `EEx`.

  * Deprecations
    * The `--with-code` flag has been changed to `--verbose`. The `--with-code`
    flag will continue to work as expected until v1.0.0, but will print a
    warning message.
