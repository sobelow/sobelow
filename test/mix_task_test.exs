defmodule SobelowTest.MixTaskTest do
  @moduledoc """
  Covers option parsing in `Mix.Tasks.Sobelow`.

  Each case appends `--version`, which is a terminal branch in the task's `cond`.
  The full option pipeline runs, application env is set, and the task returns
  without kicking off a scan.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  @conf_fixture "test/fixtures/conf/with_config"

  @env_keys [
    :details,
    :exit_on,
    :format,
    :ignored,
    :ignored_files,
    :legacy_skips,
    :out,
    :private,
    :root,
    :router,
    :skip,
    :strict,
    :threshold,
    :verbose
  ]

  defp parse(argv) do
    capture_io(fn -> Mix.Tasks.Sobelow.run(argv ++ ["--version", "--private"]) end)

    Map.new(@env_keys, &{&1, Application.get_env(:sobelow, &1)})
  end

  describe "--no-router" do
    test "is normalised to a :none router, so it round-trips through --save-config" do
      assert parse(["--no-router"]).router == :none
    end

    test "leaves the router unset when absent" do
      assert parse([]).router == nil
    end

    test "does not disturb an explicit router path" do
      assert parse(["--router", "lib/my_web/router.ex"]).router == "lib/my_web/router.ex"
    end

    test "takes precedence over an explicit router path" do
      assert parse(["--router", "lib/my_web/router.ex", "--no-router"]).router == :none
    end
  end

  describe "--legacy-skips" do
    test "defaults to off, so the skips file is rewritten sorted" do
      assert parse([]).legacy_skips == false
    end

    test "is enabled by the flag" do
      assert parse(["--legacy-skips"]).legacy_skips == true
    end
  end

  describe "defaults" do
    test "uses txt format, low threshold, and no exit status" do
      env = parse([])

      assert env.format == "txt"
      assert env.threshold == :low
      assert env.exit_on == false
      assert env.ignored == []
      assert env.ignored_files == []
      assert env.verbose == false
      assert env.skip == false
    end
  end

  describe "--ignore" do
    test "splits a comma-separated list" do
      assert parse(["-i", "XSS.Raw,Traversal"]).ignored == ["XSS.Raw", "Traversal"]
    end

    test "accepts a single module" do
      assert parse(["--ignore", "Config.CSRF"]).ignored == ["Config.CSRF"]
    end
  end

  describe "--ignore-files" do
    test "expands each path relative to the root" do
      env = parse(["--root", @conf_fixture, "--ignore-files", "config/prod.exs,lib/a.ex"])

      assert env.ignored_files == [
               Path.expand("config/prod.exs", @conf_fixture),
               Path.expand("lib/a.ex", @conf_fixture)
             ]
    end

    test "ignores empty entries" do
      assert parse(["--ignore-files", ""]).ignored_files == []
    end
  end

  describe "--exit" do
    test "bare --exit defaults to low" do
      assert parse(["--exit"]).exit_on == :low
    end

    test "accepts an explicit threshold, case-insensitively" do
      assert parse(["--exit", "Medium"]).exit_on == :medium
      assert parse(["--exit", "HIGH"]).exit_on == :high
    end

    test "an unrecognised value disables the exit status" do
      assert parse(["--exit", "nonsense"]).exit_on == false
    end
  end

  describe "--threshold" do
    test "is case-insensitive and falls back to low" do
      assert parse(["--threshold", "HIGH"]).threshold == :high
      assert parse(["--threshold", "medium"]).threshold == :medium
      assert parse(["--threshold", "nonsense"]).threshold == :low
    end
  end

  describe "--format" do
    test "is downcased" do
      assert parse(["-f", "JSON"]).format == "json"
    end

    test "the shorthand flags win over --format" do
      assert parse(["--quiet", "-f", "txt"]).format == "quiet"
      assert parse(["--compact", "-f", "txt"]).format == "compact"
      assert parse(["--flycheck", "-f", "txt"]).format == "flycheck"
    end
  end

  describe "--out" do
    test "coerces a non-machine-readable format to json" do
      assert parse(["--out", "findings.txt"]).format == "json"
    end

    test "leaves machine-readable formats alone" do
      assert parse(["--out", "findings.sarif", "-f", "sarif"]).format == "sarif"
      assert parse(["--out", "findings.json", "-f", "json"]).format == "json"
      assert parse(["--out", "findings.txt", "--quiet"]).format == "quiet"
    end
  end

  describe ".sobelow-conf" do
    test "is picked up automatically" do
      env = parse(["--root", @conf_fixture])

      assert env.format == "compact"
      assert env.exit_on == :medium
      assert env.threshold == :medium
      assert env.ignored == ["XSS.Raw"]
      assert env.verbose == true
    end

    test "CLI switches take precedence over the file" do
      env = parse(["--root", @conf_fixture, "-f", "json", "--threshold", "high"])

      assert env.format == "json"
      assert env.threshold == :high
      # Untouched by the CLI, so the file's value survives.
      assert env.exit_on == :medium
    end

    test "--no-config ignores the file entirely" do
      env = parse(["--root", @conf_fixture, "--no-config"])

      assert env.format == "txt"
      assert env.threshold == :low
      assert env.exit_on == false
      assert env.ignored == []
    end

    # The original symptom was the task aborting outright, so cover the whole
    # option-parsing path and not just `read_config_file/1`. An empty file must
    # leave the defaults intact rather than halt.
    @tag :tmp_dir
    test "an empty file leaves the defaults intact", %{tmp_dir: tmp_dir} do
      File.write!(Path.join(tmp_dir, ".sobelow-conf"), "")

      env = parse(["--root", tmp_dir])

      assert env.format == "txt"
      assert env.threshold == :low
      assert env.exit_on == false
      assert env.ignored == []
    end
  end

  describe "read_config_file/1" do
    @describetag :tmp_dir

    test "returns the parsed keyword list", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".sobelow-conf")
      File.write!(path, ~s([exit: :low, ignore: ["XSS.Raw"]]))

      assert Mix.Tasks.Sobelow.read_config_file(path) == {:ok, [exit: :low, ignore: ["XSS.Raw"]]}
    end

    test "reports an actionable error for unparseable contents", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".sobelow-conf")
      File.write!(path, "not valid [[[")

      assert {:error, message} = Mix.Tasks.Sobelow.read_config_file(path)
      assert message =~ "Could not read #{path}"
      assert message =~ "must contain a single keyword list"
      assert message =~ "--no-config"
    end

    test "rejects a parseable term that is not a keyword list", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".sobelow-conf")
      File.write!(path, ~s(%{format: "json"}))

      assert {:error, _message} = Mix.Tasks.Sobelow.read_config_file(path)
    end

    test "reports an error for a missing file", %{tmp_dir: tmp_dir} do
      assert {:error, _message} =
               Mix.Tasks.Sobelow.read_config_file(Path.join(tmp_dir, "nope"))
    end

    # A file that asks for nothing is not a misconfiguration. `.sobelow-conf` is
    # read automatically, so treating these as fatal broke scans over a file that
    # a `touch` or a truncated write was enough to produce.
    test "treats an empty file as no options", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".sobelow-conf")
      File.write!(path, "")

      assert Mix.Tasks.Sobelow.read_config_file(path) == {:ok, []}
    end

    test "treats a whitespace-only file as no options", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".sobelow-conf")
      File.write!(path, "\n\n   \n")

      assert Mix.Tasks.Sobelow.read_config_file(path) == {:ok, []}
    end

    test "treats a comment-only file as no options", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".sobelow-conf")
      File.write!(path, "# no options yet\n")

      assert Mix.Tasks.Sobelow.read_config_file(path) == {:ok, []}
    end

    # Empty is tolerated, but anything we cannot interpret must still fail loudly
    # rather than let a scan run with settings the user believed were applied.
    test "still rejects a parseable term that is merely falsy", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".sobelow-conf")
      File.write!(path, "nil")

      assert {:error, _message} = Mix.Tasks.Sobelow.read_config_file(path)
    end

    test "still rejects a non-keyword list", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, ".sobelow-conf")
      File.write!(path, ~s(["XSS.Raw"]))

      assert {:error, _message} = Mix.Tasks.Sobelow.read_config_file(path)
    end
  end
end
