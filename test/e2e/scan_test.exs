defmodule SobelowTest.E2E.ScanTest do
  @moduledoc """
  End-to-end coverage of the full scan pipeline against fixture applications.
  """

  use Sobelow.ScanCase, async: false

  describe "scanning a typical Phoenix application" do
    test "reports findings across every category the fixture exercises" do
      report = scan("basic")

      assert finding_modules(report) == [
               "Config.CSRF",
               "Config.CSWH",
               "Config.HSTS",
               "Config.HTTPS",
               "Config.Headers",
               "Config.Secrets",
               "SQL.Query",
               "Traversal.FileModule",
               "Traversal.SendFile",
               "XSS.Raw"
             ]

      assert report["total_findings"] == length(findings(report))
      assert report["sobelow_version"] =~ ~r/^\d+\.\d+\.\d+/
    end

    test "reports file and line for a function-level finding" do
      report = scan("basic")

      assert [finding] = findings_for(report, "Traversal.SendFile")

      assert finding["file"] ==
               "test/fixtures/apps/basic/lib/basic_web/controllers/page_controller.ex"

      assert finding["line"] == 5
      assert finding["variable"] == "path"
      assert finding["confidence"] == "high"
    end

    test "grades findings by whether the variable is user-controlled" do
      report = scan("basic")

      assert [send_file] = findings_for(report, "Traversal.SendFile")
      assert send_file["confidence"] == "high"

      assert [raw] = findings_for(report, "XSS.Raw")
      assert raw["confidence"] == "low"
    end
  end

  describe "--ignore" do
    test "omits ignored modules from the report" do
      report = scan("basic", ignored: ["Config", "Vuln"])

      refute Enum.any?(finding_modules(report), &String.starts_with?(&1, "Config."))
      assert "Traversal.SendFile" in finding_modules(report)
    end
  end

  describe "--ignore-files" do
    test "omits findings from ignored files" do
      ignored =
        Path.expand("test/fixtures/apps/basic/lib/basic_web/controllers/page_controller.ex")

      report = scan("basic", ignored_files: [ignored])

      refute Enum.any?(finding_modules(report), &String.starts_with?(&1, "Traversal."))
      assert "Config.Secrets" in finding_modules(report)
    end
  end

  describe "--threshold" do
    test "high excludes medium and low confidence findings" do
      report = scan("basic", threshold: :high)

      assert report["findings"]["medium_confidence"] == []
      assert report["findings"]["low_confidence"] == []
      refute report["findings"]["high_confidence"] == []
    end
  end

  describe "output formats" do
    test "sarif emits one result per finding with a rule id" do
      {stdout, _stderr} = scan_io("basic", format: "sarif")

      sarif = Jason.decode!(stdout)

      assert sarif["version"] == "2.1.0"
      assert [run] = sarif["runs"]
      assert run["tool"]["driver"]["name"] == "Sobelow"

      for result <- run["results"] do
        assert is_binary(result["ruleId"]), "expected a ruleId for #{inspect(result["message"])}"
        assert result["ruleId"] =~ ~r/^SBLW\d{3}$/
      end

      rule_ids = MapSet.new(run["tool"]["driver"]["rules"], & &1["id"])

      for result <- run["results"] do
        assert MapSet.member?(rule_ids, result["ruleId"])
      end
    end

    test "sarif regions are 1-based" do
      {stdout, _stderr} = scan_io("basic", format: "sarif")

      for result <- Jason.decode!(stdout)["runs"] |> hd() |> Map.fetch!("results") do
        region = result["locations"] |> hd() |> get_in(["physicalLocation", "region"])

        assert region["startLine"] >= 1
        assert region["startColumn"] >= 1
      end
    end

    test "quiet reports a count rather than findings" do
      {stdout, _stderr} = scan_io("basic", format: "quiet")

      assert stdout =~ ~r/^Sobelow: \d+ findings found\./
    end

    test "txt prints a banner and human-readable findings" do
      {stdout, stderr} = scan_io("basic", format: "txt")

      assert stderr =~ "Running Sobelow"
      assert stderr =~ "SCAN COMPLETE"
      assert stdout =~ "Traversal.SendFile: Directory Traversal in `send_file`"
      assert stdout =~ "Variable: path"
    end
  end
end
