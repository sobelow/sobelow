defmodule SobelowTest.E2E.ScanTest do
  @moduledoc """
  End-to-end coverage of the full scan pipeline against fixture applications.
  """

  use Sobelow.ScanCase, async: false

  describe "scanning a typical Phoenix application" do
    test "detects raw output in HEEx interpolation" do
      temp_fixture_file(
        "basic",
        "lib/basic_web/controllers/page_html/raw_interpolation.html.heex",
        "{raw(@user_input)}"
      )

      report = scan("basic")

      assert Enum.any?(findings_for(report, "XSS.Raw"), fn finding ->
               String.ends_with?(finding["file"], "raw_interpolation.html.heex")
             end)

      {sarif, _stderr} = scan_io("basic", format: "sarif")

      assert Enum.any?(Jason.decode!(sarif)["runs"] |> hd() |> Map.fetch!("results"), fn result ->
               location = hd(result["locations"])["physicalLocation"]

               String.ends_with?(
                 location["artifactLocation"]["uri"],
                 "raw_interpolation.html.heex"
               ) and
                 location["region"]["startColumn"] == 2
             end)
    end

    test "correlates a controller render with an embedded HEEx template" do
      temp_fixture_file(
        "basic",
        "lib/basic_web/controllers/album_controller.ex",
        """
        defmodule BasicWeb.AlbumController do
          use BasicWeb, :controller

          def show(conn, %{"name" => name}) do
            render(conn, :show, name: name)
          end
        end
        """
      )

      temp_fixture_file(
        "basic",
        "lib/basic_web/controllers/album_html/show.html.heex",
        "{raw(@name)}"
      )

      report = scan("basic")

      assert Enum.any?(findings_for(report, "XSS.Raw"), fn finding ->
               finding["confidence"] == "high" and
                 String.ends_with?(finding["template"] || "", "album_html/show.html.heex")
             end)
    end

    test "detects raw output in an inline HEEx sigil" do
      source =
        Enum.join(
          [
            "defmodule BasicWeb.UnsafeLive do",
            "  def render(assigns) do",
            "    ~H\"\"\"",
            "    <div>{raw(@name)}</div>",
            "    \"\"\"",
            "  end",
            "end"
          ],
          "\n"
        )

      temp_fixture_file("basic", "lib/basic_web/live/unsafe_live.ex", source)

      report = scan("basic")

      assert Enum.any?(findings_for(report, "XSS.Raw"), fn finding ->
               String.ends_with?(finding["file"], "unsafe_live.ex") and finding["line"] == 4
             end)
    end

    test "reports the line of a single-line HEEx sigil" do
      temp_fixture_file(
        "basic",
        "lib/basic_web/live/single_line_live.ex",
        "defmodule BasicWeb.SingleLineLive do\n  def render(assigns), do: ~H\"<div>{raw(@name)}</div>\"\nend\n"
      )

      report = scan("basic")

      assert Enum.any?(findings_for(report, "XSS.Raw"), fn finding ->
               String.ends_with?(finding["file"], "single_line_live.ex") and finding["line"] == 2
             end)
    end

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

  describe "endpoint configuration" do
    test "disabled HTTPS and another app's endpoint do not suppress HTTPS" do
      temp_fixture_file(
        "basic",
        "config/prod.exs",
        """
        import Config
        config :basic, BasicWeb.Endpoint, https: false, force_ssl: false
        config :other, OtherWeb.Endpoint, https: [port: 443]
        """
      )

      assert [_] = scan("basic") |> findings_for("Config.HTTPS")
    end

    test "an explicit hsts: false does not suppress HSTS" do
      temp_fixture_file(
        "basic",
        "config/prod.secret.exs",
        """
        import Config
        config :basic, BasicWeb.Endpoint,
          https: [port: 443],
          force_ssl: [hsts: false]
        """
      )

      assert [_] = scan("basic") |> findings_for("Config.HSTS")
    end

    test "a socket inherits a disabled origin check from its endpoint config" do
      temp_fixture_file(
        "basic",
        "lib/basic_web/endpoint.ex",
        """
        defmodule BasicWeb.Endpoint do
          use Phoenix.Endpoint, otp_app: :basic
          socket "/socket", BasicWeb.UserSocket, websocket: []
        end
        """
      )

      temp_fixture_file(
        "basic",
        "config/prod.exs",
        """
        import Config
        config :basic, BasicWeb.Endpoint, check_origin: false
        config :other, OtherWeb.Endpoint, check_origin: true
        """
      )

      assert [_] = scan("basic") |> findings_for("Config.CSWH")
    end

    test "another endpoint's disabled origin check does not affect the socket" do
      temp_fixture_file(
        "basic",
        "lib/basic_web/endpoint.ex",
        """
        defmodule BasicWeb.Endpoint do
          use Phoenix.Endpoint, otp_app: :basic
          socket "/socket", BasicWeb.UserSocket, websocket: []
        end
        """
      )

      temp_fixture_file(
        "basic",
        "config/prod.exs",
        """
        import Config
        config :basic, OtherWeb.Endpoint, check_origin: false
        """
      )

      assert [] == scan("basic") |> findings_for("Config.CSWH")
    end

    test "a socket inherits the base endpoint origin setting" do
      temp_fixture_file(
        "basic",
        "lib/basic_web/endpoint.ex",
        """
        defmodule BasicWeb.Endpoint do
          use Phoenix.Endpoint, otp_app: :basic
          socket "/socket", BasicWeb.UserSocket, websocket: []
        end
        """
      )

      temp_fixture_file(
        "basic",
        "config/config.exs",
        "import Config\nconfig :basic, BasicWeb.Endpoint, check_origin: false\n"
      )

      assert [_] = scan("basic") |> findings_for("Config.CSWH")
    end

    test "a production endpoint origin setting overrides the base setting" do
      temp_fixture_file(
        "basic",
        "lib/basic_web/endpoint.ex",
        """
        defmodule BasicWeb.Endpoint do
          use Phoenix.Endpoint, otp_app: :basic
          socket "/socket", BasicWeb.UserSocket, websocket: []
        end
        """
      )

      temp_fixture_file(
        "basic",
        "config/config.exs",
        "import Config\nconfig :basic, BasicWeb.Endpoint, check_origin: false\n"
      )

      temp_fixture_file(
        "basic",
        "config/prod.exs",
        "import Config\nconfig :basic, BasicWeb.Endpoint, check_origin: true\n"
      )

      assert [] == scan("basic") |> findings_for("Config.CSWH")
    end
  end

  test "reports route action reuse through the full scan pipeline" do
    temp_fixture_file(
      "basic",
      "lib/basic_web/router.ex",
      """
      defmodule BasicWeb.Router do
        use BasicWeb, :router
        scope "/", BasicWeb do
          get "/items", PageController, :index
          post "/items", PageController, :index
        end
      end
      """
    )

    assert [%{"confidence" => "high", "line" => 4, "route" => "index"}] =
             scan("basic") |> findings_for("Config.CSRFRoute")
  end

  describe "known dependency advisories" do
    test "reads a locked Hex version when deps are absent" do
      temp_fixture_file(
        "basic",
        "mix.lock",
        "%{\"plug\" => {:hex, :plug, \"1.3.0\", \"checksum\", [:mix], [], \"hexpm\"}}\n"
      )

      report = scan("basic")

      assert [finding] = findings_for(report, "Vuln.PlugNull")
      assert String.ends_with?(finding["file"], "mix.lock")

      {sarif, _stderr} = scan_io("basic", format: "sarif")

      assert Enum.any?(Jason.decode!(sarif)["runs"] |> hd() |> Map.fetch!("results"), fn result ->
               result["message"]["text"] =~ "Vuln.CookieRCE:" and
                 result["ruleId"] == Sobelow.Vuln.CookieRCE.id()
             end)
    end

    test "a dependency mixfile without a literal version does not abort the scan" do
      temp_fixture_file(
        "basic",
        "deps/coherence/mix.exs",
        "defmodule Coherence.Mixfile do\n  def project, do: [app: :coherence]\nend\n"
      )

      assert is_map(scan("basic"))
    end
  end

  test "keeps imports and controller confidence scoped to each module" do
    temp_fixture_file(
      "basic",
      "lib/basic_web/controllers/mixed.ex",
      """
      defmodule BasicWeb.SQLHelper do
        import Ecto.Adapters.SQL

        def run(term) do
          query(Repo, "SELECT \#{term}")
        end
      end

      defmodule BasicWeb.LocalController do
        use BasicWeb, :controller

        def run(conn, %{"term" => term}) do
          query(conn, "SELECT \#{term}")
        end
      end
      """
    )

    findings =
      scan("basic")
      |> findings_for("SQL.Query")
      |> Enum.filter(&String.ends_with?(&1["file"], "mixed.ex"))

    assert [%{"confidence" => "low"}] = findings
  end

  test "a direct local alias retains its parameter confidence" do
    temp_fixture_file(
      "basic",
      "lib/basic_web/controllers/alias_controller.ex",
      """
      defmodule BasicWeb.AliasController do
        use BasicWeb, :controller

        def index(conn, %{"sql" => sql}) do
          local = sql
          Repo.query(local)
          conn
        end
      end
      """
    )

    assert [%{"confidence" => "high", "variable" => "local"}] =
             scan("basic")
             |> findings_for("SQL.Query")
             |> Enum.filter(&String.ends_with?(&1["file"], "alias_controller.ex"))
  end

  test "an overwritten local alias does not retain parameter confidence" do
    temp_fixture_file(
      "basic",
      "lib/basic_web/controllers/overwritten_controller.ex",
      """
      defmodule BasicWeb.OverwrittenController do
        use BasicWeb, :controller

        def index(conn, %{"sql" => sql}) do
          local = sql
          local = source()
          Repo.query(local)
          conn
        end
      end
      """
    )

    assert [%{"confidence" => "medium", "variable" => "local"}] =
             scan("basic")
             |> findings_for("SQL.Query")
             |> Enum.filter(&String.ends_with?(&1["file"], "overwritten_controller.ex"))
  end

  describe "opt-in source paths" do
    test "includes Mix tasks only when requested" do
      temp_fixture_file(
        "basic",
        "lib/mix/tasks/risky.ex",
        "defmodule Mix.Tasks.Risky do\n  def run(cmd), do: System.cmd(cmd, [])\nend\n"
      )

      refute Enum.any?(findings_for(scan("basic"), "CI.System"), fn finding ->
               String.ends_with?(finding["file"], "risky.ex")
             end)

      assert Enum.any?(
               findings_for(scan("basic", include_mix_tasks: true), "CI.System"),
               fn finding ->
                 String.ends_with?(finding["file"], "risky.ex")
               end
             )
    end

    test "includes standalone scripts only when requested" do
      temp_fixture_file(
        "basic",
        "scripts/risky.exs",
        "defmodule Risky do\n  def run(cmd), do: System.cmd(cmd, [])\nend\n"
      )

      refute Enum.any?(findings_for(scan("basic"), "CI.System"), fn finding ->
               String.ends_with?(finding["file"], "risky.exs")
             end)

      assert Enum.any?(
               findings_for(scan("basic", include_scripts: true), "CI.System"),
               fn finding ->
                 String.ends_with?(finding["file"], "risky.exs")
               end
             )
    end
  end

  describe "output formats" do
    test "fails when the output file cannot be written" do
      out = Path.join(fixture_path("basic"), "missing/report.json")

      assert_raise Sobelow.ScanError, ~r/Could not write/, fn ->
        scan_io("basic", format: "json", out: out)
      end
    end

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

    test "sarif locations are relative to the scan root" do
      {stdout, _stderr} = scan_io("basic", format: "sarif")

      for result <- Jason.decode!(stdout)["runs"] |> hd() |> Map.fetch!("results") do
        uri =
          get_in(result, [
            "locations",
            Access.at(0),
            "physicalLocation",
            "artifactLocation",
            "uri"
          ])

        assert String.starts_with?(uri, ["lib/", "config/"])
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
