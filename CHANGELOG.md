# Changelog

## Unreleased
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
