defmodule Sobelow.AdvisoryBehaviorTest do
  use Sobelow.CoverageCase, async: false

  @cases [
    {Sobelow.Vuln.Coherence, "coherence", "0.5.1", "0.5.2"},
    {Sobelow.Vuln.Ecto, "ecto", "2.2.0", "2.2.1"},
    {Sobelow.Vuln.HeaderInject, "plug", "1.3.4", "1.3.5"},
    {Sobelow.Vuln.CookieRCE, "plug", "1.3.1", "1.3.2"},
    {Sobelow.Vuln.PlugNull, "plug", "1.3.0", "1.3.2"},
    {Sobelow.Vuln.Redirect, "phoenix", "1.3.0-rc.0", "1.3.0"}
  ]

  for {module, package, vulnerable, fixed} <- @cases do
    @tag :tmp_dir
    test "#{module} reports affected releases and rejects fixed and malformed versions", %{
      tmp_dir: dir
    } do
      lock = Path.join(dir, "mix.lock")

      for {version, count} <- [{unquote(vulnerable), 1}, {unquote(fixed), 0}, {"invalid", 0}] do
        reset_logs()

        File.write!(
          lock,
          inspect(%{unquote(package) => {:hex, String.to_atom(unquote(package)), version}})
        )

        unquote(module).run(dir)
        assert length(logged_findings()) == count

        if count == 1 do
          [finding] = logged_findings()
          assert finding.confidence == :high
          assert finding.vuln_line_no == 0
          assert finding.filename == Sobelow.Utils.normalize_path(lock)
          assert finding.fingerprint != nil
        end
      end
    end
  end

  @tag :tmp_dir
  test "missing, nonliteral, malformed and non-Hex lock entries degrade quietly", %{tmp_dir: dir} do
    assert Sobelow.Vuln.dependency_version(dir, "plug") == nil

    for contents <- [
          "%{",
          "[]",
          "%{}",
          ~s|%{"plug" => {:git, "url", "ref", []}}|,
          ~s|%{"plug" => {:hex, :plug, version()}}|
        ] do
      File.write!(Path.join(dir, "mix.lock"), contents)
      capture_io(:stderr, fn -> assert Sobelow.Vuln.dependency_version(dir, "plug") == nil end)
    end
  end

  test "dependency findings retain custom metadata in every output format" do
    for format <- ["json", "txt", "compact", "flycheck", "quiet"] do
      reset_logs()
      Application.put_env(:sobelow, :format, format)

      output =
        capture_io(fn ->
          Sobelow.Vuln.print_finding(
            "mix.lock",
            "1.3.0",
            "Plug",
            "details",
            "CVE-test",
            "CookieRCE"
          )
        end)

      assert [%Finding{confidence: :high}] = logged_findings()

      case format do
        "json" -> assert FindingLog.json("test") =~ "CVE-test"
        "txt" -> assert capture_io(fn -> FindingLog.print_txt() end) =~ "Details: details"
        "compact" -> assert output =~ "mix.lock:0"
        "flycheck" -> assert output =~ "mix.lock:0: Vuln.CookieRCE:"
        "quiet" -> assert FindingLog.quiet() =~ "1 finding"
      end
    end
  end
end
