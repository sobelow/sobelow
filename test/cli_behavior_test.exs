defmodule Sobelow.CLIBehaviorTest do
  use Sobelow.CoverageCase, async: false

  test "escript entry point and deprecated verbose flag retain their public behavior" do
    assert capture_io(fn -> Mix.Tasks.Sobelow.main(["--version", "--private"]) end) =~ "0.15.0"

    output =
      capture_io(fn -> Mix.Tasks.Sobelow.run(["--version", "--private", "--with-code"]) end)

    assert output =~ "--with-code is deprecated"
    assert Sobelow.get_env(:verbose)
  end

  test "details supports categories, individual checks and unknown names" do
    assert capture_io(fn -> Mix.Tasks.Sobelow.run(["--private", "--details", "SQL"]) end) =~
             "SQL Injection"

    assert capture_io(fn -> Mix.Tasks.Sobelow.run(["--private", "--details", "SQL.Query"]) end) =~
             "SQL Injection"

    assert capture_io(:stderr, fn ->
             Mix.Tasks.Sobelow.run(["--private", "--details", "Unknown"])
           end) =~ "valid module was not selected"
  end

  test "an empty output path retains the selected human output format" do
    capture_io(fn ->
      Mix.Tasks.Sobelow.run(["--private", "--version", "--out", "", "--format", "txt"])
    end)

    assert Sobelow.get_env(:format) == "txt"
  end

  test "category names and legacy check aliases retain their registry mappings" do
    for {name, module} <- [
          {"XSS", Sobelow.XSS},
          {"SQL", Sobelow.SQL},
          {"Misc", Sobelow.Misc},
          {"RCE", Sobelow.RCE},
          {"Traversal", Sobelow.Traversal},
          {"CI", Sobelow.CI},
          {"DOS", Sobelow.DOS},
          {"Misc.FilePath", Sobelow.Misc.FilePath},
          {"Vuln.Plug", Sobelow.Vuln.CookieRCE}
        ],
        do: assert(Sobelow.get_mod(name) == module)

    assert Sobelow.get_mod("Unknown") == nil
  end

  test "exit thresholds include all higher confidence findings and leave clean scans running" do
    for threshold <- [:high, :medium, :low] do
      assert Sobelow.exit_status(threshold, %{high: 1, medium: 0, low: 0}) == 1
      assert Sobelow.exit_status(threshold, %{high: 0, medium: 0, low: 0}) == nil
    end

    assert Sobelow.exit_status(:high, %{high: 0, medium: 1, low: 1}) == nil
    assert Sobelow.exit_status(:medium, %{high: 0, medium: 1, low: 0}) == 1
    assert Sobelow.exit_status(:medium, %{high: 0, medium: 0, low: 1}) == nil
    assert Sobelow.exit_status(:low, %{high: 0, medium: 0, low: 1}) == 1
    assert Sobelow.exit_status(false, %{high: 1, medium: 1, low: 1}) == 0
  end
end
