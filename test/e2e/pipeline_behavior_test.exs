defmodule Sobelow.PipelineBehaviorTest do
  use Sobelow.ScanCase, async: false

  @tag :tmp_dir
  test "reports can be written to a file or printed with an empty output path", %{tmp_dir: dir} do
    out = Path.join(dir, "report.json")
    assert {"", _stderr} = scan_io("basic", out: out)
    assert Jason.decode!(File.read!(out))["total_findings"] > 0
    {stdout, _stderr} = scan_io("basic", out: "")
    assert Jason.decode!(stdout)["total_findings"] > 0
  end

  test "empty router settings retain both modern and legacy discovery behavior" do
    for fixture <- ["no_router", "no_router_legacy"] do
      baseline = scan(fixture)
      {stdout, stderr} = scan_io(fixture, router: "")
      assert Jason.decode!(stdout)["findings"] == baseline["findings"]
      assert stderr =~ "cannot find the router"
    end
  end

  test "router omissions and application names do not leak into the next scan" do
    assert scan("no_router", only: ["Config.CSRF"])["total_findings"] == 0
    assert Sobelow.get_env(:ignored) == []

    Application.put_env(:sobelow, :root, fixture_path("basic"))

    stdout = ExUnit.CaptureIO.capture_io(fn -> Sobelow.run() end)
    assert [_] = stdout |> Jason.decode!() |> findings_for("Config.CSRF")
  end

  test "explicit legacy routers are resolved against the scanned root" do
    path =
      temp_fixture_file("no_router_legacy", "web/special_router.ex", """
      defmodule LegacyWeb.Router do
        use LegacyWeb, :router
        pipeline :browser do
          plug :fetch_session
        end
      end
      """)

    report = scan("no_router_legacy", router: "web/special_router.ex")
    assert [%{"file" => ^path}] = findings_for(report, "Config.CSRF")
  end

  test "a function skip followed by more definitions suppresses only its own sink" do
    path =
      temp_fixture_file("basic", "lib/multiple_skips.ex", """
      defmodule MultipleSkips do
        def reported(path), do: File.read(path)
        # sobelow_skip ["Traversal.FileModule"]
        def skipped(path), do: File.read(path)
      end
      """)

    assert [%{"line" => 2}] =
             scan("basic", skip: true)
             |> findings_for("Traversal.FileModule")
             |> Enum.filter(&String.ends_with?(&1["file"], path))
  end

  test "function skips apply across function annotations only when enabled" do
    path =
      temp_fixture_file("no_router", "lib/annotated.ex", """
      defmodule Annotated do
        # sobelow_skip ["Traversal.FileModule"]
        @doc false
        def documented(path), do: File.read(path)

        # sobelow_skip ["Traversal.FileModule"]
        @impl true
        def callback(path), do: File.read(path)

        # sobelow_skip ["Traversal.FileModule"]
        @spec read(t) :: term() when t: binary()
        # sobelow_skip ["Misc.BinToTerm"]
        defp read(path) when is_binary(path), do: File.read(path)

        def ordinary(path), do: File.read(path)
      end
      """)

    file_findings = fn skip ->
      scan("no_router", skip: skip, only: ["Traversal.FileModule"])
      |> findings_for("Traversal.FileModule")
      |> Enum.filter(&(&1["file"] == path))
    end

    all = file_findings.(false)
    assert Enum.map(all, & &1["line"]) == [4, 8, 13, 15]
    assert file_findings.(true) == [List.last(all)]
  end

  test "function skips bind to definitions in their own block only" do
    path =
      temp_fixture_file("basic", "lib/skip_boundaries.ex", """
      defmodule SkipBoundaries do
        # sobelow_skip ["Traversal.FileModule"]
        @unrelated "A module attribute"
        def after_attr(path), do: File.read(path)
        def after_nested(path) do
          if path do
            # sobelow_skip ["Traversal.FileModule"]
            :ok
          end
          File.read(path)
        end
        # sobelow_skip ["XSS.Raw"]
        # sobelow_skip ["Traversal.FileModule"]
        def skipped(path), do: File.read(path)
        def later(path), do: File.read(path)
        # sobelow_skip ["Traversal.FileModule"]
        @spec later(binary()) :: term()
        def after_other_spec(path), do: File.read(path)
      end
      """)

    assert scan("basic", skip: true)
           |> findings_for("Traversal.FileModule")
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(& &1["line"]) == [4, 10, 15, 18]
  end

  test "an ignored explicit router is never parsed by config checks" do
    path = temp_fixture_file("no_router", "custom.ex", "incomplete(")

    {_, stderr} =
      scan_io("no_router", router: "custom.ex", ignored_files: [Path.expand(path)], summary: true)

    assert stderr =~ "ignored: 1"
    assert stderr =~ "unparseable: 0"
    refute stderr =~ "custom.ex"
  end

  test "malformed skip records are retained when new records are sorted" do
    path =
      temp_fixture_file(
        "basic",
        ".sobelow-skips",
        "malformed,entry,with,extra\nType,page.ex:not-a-line,hash\n"
      )

    scan("basic", mark_skip_all: true)
    contents = File.read!(path)
    assert contents =~ "malformed,entry,with,extra\n"
    assert contents =~ "Type,page.ex:not-a-line,hash\n"
  end

  test "legacy append failures leave existing skip contents intact" do
    path = temp_fixture_file("basic", ".sobelow-skips", "# original\n")
    File.chmod!(path, 0o400)

    assert_raise Sobelow.ScanError, ~r/Could not append/, fn ->
      scan_io("basic", mark_skip_all: true, legacy_skips: true)
    end

    assert File.read!(path) == "# original\n"
  end

  test "an unreadable skip record stream does not prevent the scan" do
    path = Path.join(fixture_path("basic"), ".sobelow-skips")
    File.mkdir!(path)
    on_exit(fn -> File.rm_rf!(path) end)
    assert scan("basic", skip: true)["total_findings"] > 0
  end
end
