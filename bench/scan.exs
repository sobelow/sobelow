# MIX_ENV=test mix run --no-start bench/scan.exs --profile all --format all
Code.require_file("support.exs", __DIR__)
Sobelow.Benchmark.run(System.argv())
