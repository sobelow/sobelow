defmodule SobelowTest.E2E.RegressionTest do
  @moduledoc """
  Regression coverage for crash-class bugs. Each `describe` block names the
  behaviour that used to abort a scan.
  """

  use Sobelow.ScanCase, async: false

  describe "Config.Secrets with values that are not plain string literals" do
    test "heredoc and escaped-quote secrets are reported instead of crashing the scan" do
      report = scan("secrets")

      keys =
        report
        |> findings_for("Config.Secrets")
        |> Enum.map(& &1["key"])
        |> Enum.sort()

      assert keys == ["password", "secret_key_base", "signing_secret"]
    end

    test "falls back to the config line when the secret's own line cannot be located" do
      report = scan("secrets")

      by_key =
        report
        |> findings_for("Config.Secrets")
        |> Map.new(&{&1["key"], &1["line"]})

      # Heredoc: unmatchable by literal substitution, so we report the `config` line.
      assert by_key["signing_secret"] == 5
      # Escaped quote: likewise.
      assert by_key["password"] == 11
    end

    test "reports the secret's own line when the config spans multiple lines" do
      report = scan("secrets")

      by_key =
        report
        |> findings_for("Config.Secrets")
        |> Map.new(&{&1["key"], &1["line"]})

      # The `config` call starts on line 15; the secret itself is on line 16.
      assert by_key["secret_key_base"] == 16
    end
  end

  describe "unparseable sources" do
    test "a malformed .ex file is skipped without aborting the scan" do
      temp_fixture_file("malformed", "lib/malformed_web/controllers/broken.ex", """
      defmodule MalformedWeb.Broken do
        def index(, do: 1
      end
      """)

      report = scan("malformed")

      assert "Traversal.SendFile" in finding_modules(report)
    end

    test "a malformed template is skipped without aborting the scan" do
      temp_fixture_file(
        "malformed",
        "lib/malformed_web/controllers/page_html/broken.html.heex",
        "<div><%= if x do %></div>\n"
      )

      report = scan("malformed")

      assert "Traversal.SendFile" in finding_modules(report)
    end

    test "both at once still produce the remaining findings" do
      temp_fixture_file("malformed", "lib/malformed_web/controllers/broken.ex", "defmodule (\n")

      temp_fixture_file(
        "malformed",
        "lib/malformed_web/controllers/page_html/broken.html.heex",
        "<%= end %>\n"
      )

      report = scan("malformed")

      assert "Traversal.SendFile" in finding_modules(report)
    end
  end

  describe "Parse.ast/1 syntax error reporting" do
    test "formats Elixir >= 1.13 keyword-list locations" do
      assert Sobelow.Parse.format_location(line: 2, column: 8) == "2:8:"
    end

    test "formats a bare line number from older Elixir releases" do
      assert Sobelow.Parse.format_location(2) == "2:"
    end

    test "tolerates a location with no line" do
      assert Sobelow.Parse.format_location([]) == ""
      assert Sobelow.Parse.format_location(nil) == ""
    end

    test "formats an error given as a prefix/suffix pair around the token" do
      assert Sobelow.Parse.format_error({"missing terminator: ", " (for \"do\")"}, "end") ==
               "missing terminator: end (for \"do\")"
    end

    test "formats a plain binary error" do
      assert Sobelow.Parse.format_error("unexpected reserved word: ", "end") ==
               "unexpected reserved word: end"
    end

    test "produces a real message for the error shape Elixir actually returns" do
      {:error, {location, err, token}} =
        Code.string_to_quoted("defmodule A do\n  def x(, do: 1\nend", columns: true)

      message =
        "#{Sobelow.Parse.format_location(location)} #{Sobelow.Parse.format_error(err, token)}"

      assert message =~ ~r/^\d+:\d+: /
      refute message =~ "line:"
    end
  end

  describe "version check cache" do
    setup do
      dir =
        Path.join(
          System.tmp_dir!(),
          "sobelow-version-check-#{System.unique_integer([:positive])}"
        )

      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)

      {:ok, dir: dir}
    end

    test "reads a well-formed timestamp", %{dir: dir} do
      file = Path.join(dir, "vsn")
      File.write!(file, "sobelow-1700000000")

      assert Sobelow.last_version_check(file) == {:ok, 1_700_000_000}
    end

    test "treats a corrupt cache file as unknown rather than aborting", %{dir: dir} do
      file = Path.join(dir, "vsn")
      File.write!(file, "garbage")

      assert Sobelow.last_version_check(file) == :error
    end

    test "treats a non-numeric timestamp as unknown", %{dir: dir} do
      file = Path.join(dir, "vsn")
      File.write!(file, "sobelow-notanumber")

      assert Sobelow.last_version_check(file) == :error
    end

    test "treats a missing cache file as unknown", %{dir: dir} do
      assert Sobelow.last_version_check(Path.join(dir, "does-not-exist")) == :error
    end

    test "treats a directory as unknown rather than raising", %{dir: dir} do
      assert Sobelow.last_version_check(dir) == :error
    end
  end

  describe "SOBELOW_HOME" do
    test "is treated as the directory holding the cache file" do
      System.put_env("SOBELOW_HOME", "/tmp/sobelow-home-test")
      on_exit(fn -> System.delete_env("SOBELOW_HOME") end)

      assert Sobelow.version_check_file() == "/tmp/sobelow-home-test/sobelow-vsn-check"
    end

    test "defaults to ~/.sobelow when unset" do
      System.delete_env("SOBELOW_HOME")

      assert Sobelow.version_check_file() ==
               Path.join(Path.expand("~/.sobelow"), "sobelow-vsn-check")
    end
  end

  # https://github.com/sobelow/sobelow/issues/30 — a project with its own
  # `query/1` got a SQL injection finding on every call to it.
  describe "SQL.Query on unqualified calls" do
    defp sql_findings_in(report, path) do
      report
      |> findings_for("SQL.Query")
      |> Enum.filter(&String.ends_with?(&1["file"], path))
    end

    test "a local function named query/1 is not reported" do
      temp_fixture_file("basic", "lib/basic/local_query.ex", """
      defmodule Basic.LocalQuery do
        def sobelow_test(arg), do: query(arg)
        def query(arg), do: 42
      end
      """)

      report = scan("basic")

      assert sql_findings_in(report, "lib/basic/local_query.ex") == []
      # The rest of the scan is untouched: the fixture's own qualified
      # `Ecto.Adapters.SQL.query/3` is still found.
      assert length(findings_for(report, "SQL.Query")) == 1
    end

    test "an unqualified query/3 is reported when the file imported Ecto.Adapters.SQL" do
      temp_fixture_file("basic", "lib/basic/imported_query.ex", """
      defmodule Basic.ImportedQuery do
        import Ecto.Adapters.SQL

        def run(%{"sql" => sql}), do: query(Repo, sql, [])
      end
      """)

      report = scan("basic")

      assert [finding] = sql_findings_in(report, "lib/basic/imported_query.ex")
      assert finding["variable"] == "sql"
    end

    test "an unqualified query/1 is reported inside an Ecto.Repo" do
      temp_fixture_file("basic", "lib/basic/repo.ex", """
      defmodule Basic.Repo do
        use Ecto.Repo, otp_app: :basic, adapter: Ecto.Adapters.Postgres

        def run(%{"sql" => sql}), do: query(sql)
      end
      """)

      report = scan("basic")

      assert [finding] = sql_findings_in(report, "lib/basic/repo.ex")
      assert finding["variable"] == "sql"
    end

    test "an unrelated module ending in SQL does not re-enable unqualified matching" do
      temp_fixture_file("basic", "lib/basic/unrelated.ex", """
      defmodule Basic.Unrelated do
        import Some.Other.SQL

        def run(%{"sql" => sql}), do: query(sql)
      end
      """)

      report = scan("basic")

      assert sql_findings_in(report, "lib/basic/unrelated.ex") == []
    end
  end

  describe "Parse.normalize_finding/1" do
    test "renders a dot-access variable rather than leaking the interpolation source" do
      dot_access = {:., [line: 1], [{:conn, [line: 1], nil}, :body_params]}

      assert Sobelow.Parse.normalize_finding({:finding, dot_access}) ==
               {:finding, "conn.body_params"}
    end
  end
end
