defmodule Sobelow.CompatibilityTest do
  use Sobelow.ScanCase, async: false
  @fixture "test/fixtures/compatibility/v0_15_0.json"
  # Parser metadata is part of the historical hash. This capture qualifies
  # hashes on its runtime; output and rule contracts apply on the full matrix.
  @captured_parser String.starts_with?(System.version(), "1.20.")
  @parser_family System.version() |> String.split(".") |> Enum.take(2) |> Enum.join(".")

  test "existing facade functions and traversal callbacks remain callable" do
    # Captured before the module extraction; additions are allowed.
    "test/fixtures/compatibility/public_api.json"
    |> File.read!()
    |> Jason.decode!()
    |> Enum.each(fn {name, functions} ->
      module = String.to_existing_atom(name)
      assert Code.ensure_loaded?(module)

      for [name, arity] <- functions do
        assert function_exported?(module, String.to_existing_atom(name), arity),
               "#{inspect(module)}.#{name}/#{arity} is missing"
      end
    end)
  end

  test "existing findings retain the 0.15.0 output and fingerprint contracts" do
    expected = @fixture |> File.read!() |> Jason.decode!()
    # The release version changes; the complete historical findings stay fixed.
    expected_report =
      Map.put(expected["report"], "sobelow_version", to_string(Application.spec(:sobelow, :vsn)))

    assert scan("basic") == expected_report

    contracts =
      Sobelow.FindingLog.log()
      |> Map.values()
      |> List.flatten()
      |> Enum.map(fn {_details, finding, _} ->
        Map.take(Map.from_struct(finding), [
          :type,
          :filename,
          :vuln_line_no,
          :vuln_variable,
          :confidence,
          :fingerprint,
          :legacy_fingerprint
        ])
      end)
      |> Enum.sort_by(&{&1.filename, &1.vuln_line_no, &1.type})
      |> Jason.encode!()
      |> Jason.decode!()

    strip_hashes = fn contracts ->
      Enum.map(contracts, &Map.drop(&1, ["fingerprint", "legacy_fingerprint"]))
    end

    assert strip_hashes.(contracts) == strip_hashes.(expected["contracts"])
    if @captured_parser, do: assert(contracts == expected["contracts"])
  end

  test "rule IDs and SARIF result fields retain the release contracts" do
    expected = @fixture |> File.read!() |> Jason.decode!()

    ids =
      Map.new(Sobelow.finding_modules(), fn mod ->
        {String.replace_prefix(Atom.to_string(mod), "Elixir.Sobelow.", ""), mod.id()}
      end)

    assert Map.take(ids, Map.keys(expected["rule_ids"])) == expected["rule_ids"]
    {stdout, _stderr} = scan_io("basic", format: "sarif")
    results = hd(Jason.decode!(stdout)["runs"])["results"]
    strip_hashes = fn results -> Enum.map(results, &Map.delete(&1, "partialFingerprints")) end
    expected_results = release_columns(expected["sarif_results"])
    assert strip_hashes.(results) == strip_hashes.(expected_results)
    if @captured_parser, do: assert(results == expected["sarif_results"])
  end

  # Elixir changed both qualified-call and EEx column metadata. These columns
  # come from the unmodified release on each older parser, not the new scanner.
  # Keep every result field, including both columns, in the comparison.
  defp release_columns(results) do
    captures =
      "test/fixtures/compatibility/v0_15_0_columns.json"
      |> File.read!()
      |> Jason.decode!()
      |> Map.fetch!("captures")

    case Map.get(captures, @parser_family) do
      nil ->
        results

      %{"columns" => columns} ->
        Enum.map(results, fn result ->
          column = Map.fetch!(columns, result["ruleId"])

          update_in(
            result,
            ["locations", Access.all(), "physicalLocation", "region"],
            fn region ->
              Map.merge(region, %{"startColumn" => column, "endColumn" => column})
            end
          )
        end)
    end
  end

  for fixture <- ["v0_15_0.skips", "legacy.skips"] do
    @tag skip: not @captured_parser
    test "historical #{fixture} still suppresses unchanged findings" do
      contents = File.read!("test/fixtures/compatibility/" <> unquote(fixture))
      temp_fixture_file("basic", ".sobelow-skips", contents)
      assert scan("basic", skip: true)["total_findings"] == 0
    end
  end
end
