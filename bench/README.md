# Scan benchmarks

## Run and compare

```sh
# One source/config profile, quiet output; defaults to five measured runs.
MIX_ENV=test mix run --no-start bench/scan.exs

# All workloads and output formats. Memory sampling runs separately.
MIX_ENV=test mix run --no-start bench/scan.exs --profile all --format all --memory

# Capture a reviewable reference before editing the analyzer.
MIX_ENV=test mix run --no-start bench/scan.exs --profile all --format all --save-reference /tmp/scan-contracts.json --out /tmp/before.json

# Reject any changed findings or rendered output after editing.
MIX_ENV=test mix run --no-start bench/scan.exs --profile all --format all --reference /tmp/scan-contracts.json --out /tmp/after.json
```

Selections are `--profile mixed|config|phoenix|pipelines|large-functions|small-files|heex|all`
and `--format quiet|json|sarif|all`. `--files` and `--endpoints` customize only
`mixed`; `--runs` controls measured iterations. Dimensions must be positive.

The script generates source-only applications in unique temporary directories
and removes them, including on failures. No target code is compiled or executed.
Each combination warms module loading, then measures fresh scans with fresh
finding processes and caches. Timing includes discovery, preparation, checks,
collection and output; it excludes Mix startup, compilation, fixture generation,
and contract hashing. Source preparation and reporting are included.

Every measured iteration must produce the same findings and output. References
require the same Elixir version and OTP major version. They compare all Finding
fields, including both fingerprints and original function/sink ASTs, plus the
rendered report. Root paths are normalized; maps are canonicalized before
hashing. Changing a fixture or detection behaviour requires reviewing the
reference difference, not silently regenerating the reference.

`--memory` samples total BEAM VM memory every 5 ms during a separate scan. It
reports baseline, sampled peak and increase. Sampling can miss short peaks;
allocator/GC state and other VM processes affect the readings. Memory sampling
and hashing do not run inside the reported timing measurements. Reductions are
whole-VM counters around the timed scan, so background work can affect them.

## Workloads

| Profile | Generated work |
| --- | --- |
| mixed | 200 files, ten `File.read/1` functions each, 400 endpoint settings |
| config | 20 files, ten functions each, 4,000 endpoint settings |
| phoenix | 24 controllers, five render actions plus response/inline HEEx functions each; 24 templates with EEx, body/attribute interpolations, comments and disabled regions |
| pipelines | 40 files, ten functions each, twenty pipe stages before a sink |
| large-functions | 10 files, two functions each, 100 groups of aliases, file sinks and conditional atom sinks per function |
| small-files | 1,000 files, two functions each |
| heex | One controller and a template with 4,000 alternating body/attribute interpolations |

These are synthetic stress profiles, not production throughput guarantees.
The large-function case intentionally emits many findings sharing a large
function AST, exercising collection and source retention. It exaggerates the
benefit of deduplicating that source compared with ordinary projects.

## Results for this optimization batch

Local macOS on Apple Silicon, Elixir 1.20.4 / OTP 29, 14 schedulers. Baseline
medians use three measured runs; optimized medians use five. The baseline is the
feature branch before this speed batch, including the earlier functionality
improvements. These results do not compare against an unchanged 0.15.0 release.

| Profile | Format | Before ms | After ms | Ratio | Findings |
| --- | --- | ---: | ---: | ---: | ---: |
| mixed | quiet | 47.721 | 23.198 | 2.06x | 2000 |
| mixed | json | 67.476 | 41.971 | 1.61x | 2000 |
| mixed | sarif | 115.711 | 87.575 | 1.32x | 2000 |
| config | quiet | 34.745 | 31.883 | 1.09x | 200 |
| config | json | 37.310 | 33.698 | 1.11x | 200 |
| config | sarif | 44.602 | 42.043 | 1.06x | 200 |
| phoenix | quiet | 120.501 | 17.233 | 6.99x | 1200 |
| phoenix | json | 131.434 | 29.106 | 4.52x | 1200 |
| phoenix | sarif | 162.481 | 57.075 | 2.85x | 1200 |
| pipelines | quiet | 105.828 | 21.095 | 5.02x | 400 |
| pipelines | json | 110.140 | 25.562 | 4.31x | 400 |
| pipelines | sarif | 128.484 | 34.988 | 3.67x | 400 |
| large-functions | quiet | 2019.417 | 25.678 | 78.64x | 4000 |
| large-functions | json | 2342.193 | 66.654 | 35.14x | 4000 |
| large-functions | sarif | 2600.385 | 143.220 | 18.16x | 4000 |
| small-files | quiet | 122.529 | 74.332 | 1.65x | 2000 |
| small-files | json | 118.148 | 93.585 | 1.26x | 2000 |
| small-files | sarif | 172.966 | 137.427 | 1.26x | 2000 |
| heex | quiet | 245.254 | 89.825 | 2.73x | 4006 |
| heex | json | 279.050 | 134.336 | 2.08x | 4006 |
| heex | sarif | 388.825 | 232.895 | 1.67x | 4006 |

Raw captures: [before](results/before.json), [after](results/after.json).
The original timing capture used noncanonical serialization for full Finding
maps; those unstable digests are omitted from `before.json`. Its canonical output
hashes and finding counts match the later qualification. Complete canonical
Finding contracts were separately checked against the prior parsing,
metadata, HEEx, fingerprint and collection paths, then matched by all 21
optimized workload/format combinations. The qualified reference is
[contracts-elixir-1.20.4-otp-29.json](results/contracts-elixir-1.20.4-otp-29.json).

For example, on the captured runtime:

```sh
MIX_ENV=test mix run --no-start bench/scan.exs --profile all --format all --reference bench/results/contracts-elixir-1.20.4-otp-29.json
```

The changes share function call/pipe/parameter analysis, consume HEEx closing
brace candidates incrementally, retain each function source once per finding
batch, reuse sorted reports and counts, prepare files with bounded concurrency,
and pass smaller lexical contexts. Skip lookups use scan-local ETS state. Cache
statistics use per-worker counters to avoid a shared hot key.
Module definitions nested inside functions, attributes or other captured
declarations retain the existing metadata extraction path and its rewritten AST.

Lexical keys use exact deterministic binary encoding where supported, preserving
original ASTs in findings. Older OTP releases retain the original AST lookup
keys when that encoding option is unavailable. The compatibility fallback is
covered by unit tests; the full older Elixir/OTP matrix still requires CI.

Performance thresholds are not asserted in CI. For a different checkout/runtime,
compile first, use matching dimensions/formats, and review complete contracts
before interpreting timings. Cross-release changes can legitimately add findings
and make a throughput comparison involve different analysis work.

## Earlier release comparison

Before this speed batch, the original simpler benchmark recorded these five-run
medians on the same runtime:

| Original profile | Release `4eb7d16` | Earlier feature branch | Findings |
| --- | ---: | ---: | ---: |
| 200 source files, 400 endpoint settings | 47.253 ms | 47.617 ms | 2,000 |
| 20 source files, 4,000 endpoint settings | 119.007 ms | 32.061 ms | 200 |

Those measurements qualified the earlier per-scan parsing cache, and did not
cover the expanded template, pipeline, large-function or output workloads.
