defmodule SobelowTest.E2E.GithubTest do
  use Sobelow.ScanCase, async: false

  import ExUnit.CaptureIO

  setup do
    workspace = System.get_env("GITHUB_WORKSPACE")
    System.delete_env("GITHUB_WORKSPACE")

    on_exit(fn ->
      if workspace,
        do: System.put_env("GITHUB_WORKSPACE", workspace),
        else: System.delete_env("GITHUB_WORKSPACE")
    end)

    :ok
  end

  defp cli_scan(root, opts \\ []) do
    capture_io(fn ->
      Mix.Tasks.Sobelow.run(["--private", "--root", root, "--format", "github"] ++ opts)
    end)
  end

  test "emits workflow annotations with confidence and escaped filenames" do
    temp_fixture_file(
      "basic",
      "lib/basic_web/controllers/annotated,finding_controller.ex",
      """
      defmodule BasicWeb.AnnotatedFindingController do
        def show(conn, %{"path" => path}), do: send_file(conn, 200, path)
      end
      """
    )

    {stdout, stderr} = scan_io("basic", format: "github")

    assert stdout =~
             ~r/^::warning file=.*page_controller\.ex,line=5,endLine=5,col=\d+::Sobelow: Traversal\.SendFile: Directory Traversal in `send_file` \(high confidence\)$/m

    assert stdout =~ "annotated%2Cfinding_controller.ex,line=2,endLine=2,col="
    refute stderr =~ "Running Sobelow"
  end

  test "emits annotations for findings without a line number" do
    {stdout, _stderr} = scan_io("basic", format: "github")

    assert stdout =~
             "::warning file=test/fixtures/apps/basic/config/prod.secret.exs," <>
               "line=1,endLine=1,col=1::" <>
               "Sobelow: Config.HSTS: HSTS Not Enabled (medium confidence)"
  end

  test "emits nothing when there are no findings" do
    all_categories = ~w(XSS SQL Traversal RCE Misc Config CI DOS Vuln)
    {stdout, _stderr} = scan_io("basic", format: "github", ignored: all_categories)
    assert stdout == ""
  end

  test "the CLI accepts github with relative and absolute scan roots" do
    for root <- [fixture_path("basic"), Path.expand(fixture_path("basic"))] do
      assert cli_scan(root) =~
               "file=test/fixtures/apps/basic/lib/basic_web/controllers/page_controller.ex,"
    end
  end

  test "subdirectory workflows use repository relative locations" do
    System.put_env("GITHUB_WORKSPACE", File.cwd!())

    for root <- [".", Path.expand(fixture_path("basic"))] do
      output = File.cd!(fixture_path("basic"), fn -> cli_scan(root) end)

      assert output =~
               "file=test/fixtures/apps/basic/lib/basic_web/controllers/page_controller.ex,"
    end
  end

  test "scans with a parent-relative root preserve repository paths" do
    System.put_env("GITHUB_WORKSPACE", File.cwd!())
    output = File.cd!(fixture_path("no_router"), fn -> cli_scan("../basic") end)

    assert output =~
             "file=test/fixtures/apps/basic/lib/basic_web/controllers/page_controller.ex,"
  end

  test "an absolute root works outside Actions without changing logged findings" do
    {_stdout, _stderr} = scan_io("basic", format: "github")
    original = Sobelow.FindingLog.log()
    output = cli_scan(Path.expand(fixture_path("basic")))

    assert output =~
             "file=test/fixtures/apps/basic/lib/basic_web/controllers/page_controller.ex,"

    # Only rendered annotation locations change. Findings remain in Sobelow's
    # historical path form, which feeds both existing skip fingerprints.
    normalized_root = Sobelow.Utils.normalize_path(Path.expand(fixture_path("basic")))
    current = Sobelow.FindingLog.log()

    for severity <- [:high, :medium, :low] do
      relative = Map.fetch!(original, severity)
      absolute = Map.fetch!(current, severity)
      assert length(relative) == length(absolute)

      for {{_, old, _}, {_, new, _}} <- Enum.zip(relative, absolute) do
        assert String.starts_with?(new.filename, normalized_root <> "/")
        assert old.fingerprint == new.fingerprint
        assert old.legacy_fingerprint == new.legacy_fingerprint
      end
    end
  end

  @tag :tmp_dir
  test "the CLI writes annotations to an output file", %{tmp_dir: tmp_dir} do
    out = Path.join(tmp_dir, "findings.log")
    assert cli_scan(fixture_path("basic"), ["--out", out]) == ""
    assert File.read!(out) =~ "::warning file=test/fixtures/apps/basic/"
  end

  test "thresholds and existing skip files are honored" do
    {output, _stderr} = scan_io("basic", format: "github", threshold: :high)
    assert output =~ "(high confidence)"
    refute output =~ "(medium confidence)"
    refute output =~ "(low confidence)"

    # Parser metadata contributes to fingerprints and differs across supported
    # Elixir versions. Baseline this runtime, then consume its persisted skips.
    temp_fixture_file("basic", ".sobelow-skips", "")
    scan_io("basic", format: "github", mark_skip_all: true)

    {output, _stderr} = scan_io("basic", format: "github", skip: true)
    assert output == ""
  end
end
