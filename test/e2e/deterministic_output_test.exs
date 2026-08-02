defmodule Sobelow.DeterministicOutputTest do
  @moduledoc """
  Scans run their per-file and per-template work in parallel, so findings are
  logged in whatever order the tasks happen to finish. Reports are sorted by
  location before being emitted so that the same project always produces the
  same output — otherwise diffing two runs, or committing a report, is useless.
  """
  use Sobelow.ScanCase

  @runs 5

  defp outputs(fixture, format) do
    Enum.map(1..@runs, fn _ ->
      {stdout, _stderr} = scan_io(fixture, format: format)
      stdout
    end)
  end

  for format <- ["json", "txt", "sarif", "compact"] do
    test "#{format} output is identical across runs" do
      assert [_single] = "basic" |> outputs(unquote(format)) |> Enum.uniq()
    end
  end

  # JSON groups findings by confidence, so the ordering guarantee is within each
  # bucket rather than across the whole report.
  test "findings are ordered by file, then line within each confidence bucket" do
    report = scan("basic", format: "json")

    for confidence <- ["high_confidence", "medium_confidence", "low_confidence"] do
      locations =
        report
        |> get_in(["findings", confidence])
        |> List.wrap()
        |> Enum.map(&{Map.fetch!(&1, "file"), Map.get(&1, "line", 0)})

      assert locations == Enum.sort(locations), "#{confidence} is not sorted by location"
    end
  end

  # `Config.HSTS` has no function, line, or variable to report, so the header is
  # the whole finding. Printing the default metadata block for it emitted
  # placeholder junk (`Line: 0`, `Function: :`, `Variable:`).
  test "a finding with no location metadata prints only its header" do
    {stdout, _stderr} = scan_io("basic", format: "txt")

    [hsts_section | _] =
      stdout
      |> String.split("-----")
      |> Enum.filter(&String.contains?(&1, "HSTS Not Enabled"))

    refute hsts_section =~ "Line: 0"
    refute hsts_section =~ "Function: :"
    refute hsts_section =~ "Variable:"
  end
end
