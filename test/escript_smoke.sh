#!/usr/bin/env bash
set -euo pipefail

scan_tmp=$(mktemp -d)
trap 'rm -rf "$scan_tmp"' EXIT

expect_status() {
  local expected=$1
  shift
  local actual=0
  ./sobelow "$@" > "$scan_tmp/stdout" 2> "$scan_tmp/stderr" || actual=$?
  if [ "$actual" -ne "$expected" ]; then
    cat "$scan_tmp/stderr" >&2
    printf 'Expected exit %s, got %s\n' "$expected" "$actual" >&2
    exit 1
  fi
}

expect_status 0 --private --root test/fixtures/apps/basic --format sarif
elixir -pa _build/prod/lib/jason/ebin -e '
  report = System.argv() |> hd() |> File.read!() |> Jason.decode!()
  [run] = report["runs"]
  true = report["version"] == "2.1.0"
  true = run["results"] != []
  true = Enum.all?(run["results"], &is_binary(&1["ruleId"]))
' "$scan_tmp/stdout"

expect_status 0 --private --with-code --root test/fixtures/apps/basic --format quiet

expect_status 1 --private --root "$scan_tmp/missing"
grep -q 'application' "$scan_tmp/stderr"
expect_status 1 --private --format jsson
grep -q 'Invalid --format' "$scan_tmp/stderr"
expect_status 1 --private --exit high --root test/fixtures/apps/basic --format json
expect_status 1 --private --exit medium --root test/fixtures/apps/basic --format json
expect_status 1 --private --exit low --root test/fixtures/apps/basic --format json
for threshold in high medium low; do
  expect_status 0 --private --exit "$threshold" --root test/fixtures/apps/basic --format quiet \
    --ignore Config,XSS,SQL,CI,RCE,DOS,Traversal,Misc,Vuln
done

cp -R test/fixtures/apps/basic "$scan_tmp/app"
printf 'defmodule Broken do\n def nope(\n' > "$scan_tmp/app/lib/broken.ex"
expect_status 0 --private --root "$scan_tmp/app" --format json --summary
grep -q 'unparseable: 1' "$scan_tmp/stderr"
expect_status 2 --private --root "$scan_tmp/app" --strict
grep -q 'broken.ex' "$scan_tmp/stderr"
rm "$scan_tmp/app/lib/broken.ex"

mkdir -p "$scan_tmp/app/lib/basic_web/templates/page"
printf '<%%= raw(' > "$scan_tmp/app/lib/basic_web/templates/page/broken.html.eex"
expect_status 2 --private --root "$scan_tmp/app" --strict
grep -q 'broken.html.eex' "$scan_tmp/stderr"
rm "$scan_tmp/app/lib/basic_web/templates/page/broken.html.eex"

printf 'defmodule BrokenInline do\n def show(body), do: ~H"{raw(@body)"\nend\n' > "$scan_tmp/app/lib/broken_inline.ex"
expect_status 2 --private --root "$scan_tmp/app" --strict
grep -q 'broken_inline.ex' "$scan_tmp/stderr"
rm "$scan_tmp/app/lib/broken_inline.ex"

printf 'reviewed-fingerprint\n' > "$scan_tmp/app/.sobelow-skips"
expect_status 0 --private --root "$scan_tmp/app" --clear-skip
test ! -e "$scan_tmp/app/.sobelow-skips"
expect_status 0 --private --root "$scan_tmp/app" --clear-skip

printf '[invalid(\n' > "$scan_tmp/app/.sobelow-conf"
expect_status 1 --private --root "$scan_tmp/app"
grep -q 'configuration file' "$scan_tmp/stderr"
printf 'Escript smoke checks passed\n'
