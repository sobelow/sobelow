defmodule Sobelow.PipelineSkipTest do
  @moduledoc """
  End-to-end coverage for `# sobelow_skip` comments on Phoenix router pipelines.

  The unit tests in `test/config` exercise `Config.get_unskipped_pipelines/2`
  directly. These drive the whole `Sobelow.run/0` pipeline, which is what
  actually rewrites the comment into a `@sobelow_skip` attribute and honours it.
  """
  use Sobelow.ScanCase

  @router_path "lib/basic_web/router.ex"

  defp router(skip_comment) do
    """
    defmodule BasicWeb.Router do
      use BasicWeb, :router

      #{skip_comment}
      pipeline :browser do
        plug(:accepts, ["html"])
        plug(:fetch_session)
      end

      scope "/", BasicWeb do
        pipe_through(:browser)

        get("/", PageController, :index)
      end
    end
    """
  end

  test "the unmodified router reports CSRF and Headers under --skip" do
    mods = finding_modules(scan("basic", skip: true))

    assert "Config.CSRF" in mods
    assert "Config.Headers" in mods
  end

  test "a pipeline skip comment suppresses only the listed checks" do
    temp_fixture_file("basic", @router_path, router(~s(# sobelow_skip ["Config.CSRF"])))

    mods = finding_modules(scan("basic", skip: true))

    refute "Config.CSRF" in mods
    assert "Config.Headers" in mods
  end

  test "a pipeline skip comment can list several checks" do
    temp_fixture_file(
      "basic",
      @router_path,
      router(~s(# sobelow_skip ["Config.CSRF", "Config.Headers"]))
    )

    mods = finding_modules(scan("basic", skip: true))

    refute "Config.CSRF" in mods
    refute "Config.Headers" in mods
  end

  test "the parent `Config` module suppresses every Config check on the pipeline" do
    temp_fixture_file("basic", @router_path, router(~s(# sobelow_skip ["Config"])))

    mods = finding_modules(scan("basic", skip: true))

    refute "Config.CSRF" in mods
    refute "Config.Headers" in mods
  end

  test "a pipeline skip comment is ignored without --skip" do
    temp_fixture_file(
      "basic",
      @router_path,
      router(~s(# sobelow_skip ["Config.CSRF", "Config.Headers"]))
    )

    mods = finding_modules(scan("basic", skip: false))

    assert "Config.CSRF" in mods
    assert "Config.Headers" in mods
  end

  test "an unrelated check listed on a pipeline does not suppress the pipeline" do
    temp_fixture_file("basic", @router_path, router(~s(# sobelow_skip ["XSS.Raw"])))

    mods = finding_modules(scan("basic", skip: true))

    assert "Config.CSRF" in mods
    assert "Config.Headers" in mods
  end

  test "a pipeline skip does not leak onto the next function in the router" do
    router = """
    defmodule BasicWeb.Router do
      use BasicWeb, :router

      # sobelow_skip ["Traversal.SendFile"]
      pipeline :browser do
        plug(:accepts, ["html"])
        plug(:fetch_session)
      end

      def download(conn, %{"path" => path}) do
        send_file(conn, 200, path)
      end
    end
    """

    temp_fixture_file("basic", @router_path, router)

    assert router_finding?(scan("basic", skip: true), "Traversal.SendFile"),
           "the skip belonged to the pipeline, so `download/2` must still be scanned"
  end

  # The reproduction from https://github.com/sobelow/sobelow/issues/27: a real
  # router has more than one pipeline, and the skip has to land on the annotated
  # one only.
  test "a pipeline skip does not carry over to the next pipeline" do
    router = """
    defmodule BasicWeb.Router do
      use BasicWeb, :router

      # sobelow_skip ["Config.CSRF"]
      pipeline :annotated do
        plug(:accepts, ["html"])
        plug(:fetch_session)
      end

      pipeline :unannotated do
        plug(:accepts, ["html"])
        plug(:fetch_session)
      end
    end
    """

    temp_fixture_file("basic", @router_path, router)

    pipelines =
      scan("basic", skip: true)
      |> findings_for("Config.CSRF")
      |> Enum.map(& &1["pipeline"])

    assert pipelines == ["unannotated"]
  end

  # Comments and blank lines do not appear in the AST, so the rewritten
  # `@sobelow_skip` attribute is still the statement immediately before the
  # pipeline. Worth pinning: routers are often written this way.
  test "a blank line between the comment and the pipeline does not break the association" do
    router = """
    defmodule BasicWeb.Router do
      use BasicWeb, :router

      # sobelow_skip ["Config.CSRF"]

      pipeline :browser do
        plug(:accepts, ["html"])
        plug(:fetch_session)
      end
    end
    """

    temp_fixture_file("basic", @router_path, router)

    refute "Config.CSRF" in finding_modules(scan("basic", skip: true))
  end

  test "a function-level skip in the router still works" do
    router = """
    defmodule BasicWeb.Router do
      use BasicWeb, :router

      pipeline :browser do
        plug(:accepts, ["html"])
        plug(:fetch_session)
      end

      # sobelow_skip ["Traversal.SendFile"]
      def download(conn, %{"path" => path}) do
        send_file(conn, 200, path)
      end
    end
    """

    temp_fixture_file("basic", @router_path, router)

    refute router_finding?(scan("basic", skip: true), "Traversal.SendFile")
  end

  # The spacing around the marker and inside the list carries no meaning, so
  # being strict about it only produced comments that looked right and did
  # nothing. Each of these used to be ignored in silence.
  describe "skip comment spacing" do
    for {name, comment} <- [
          {"no space after the hash", ~S(#sobelow_skip ["Config.CSRF"])},
          {"several spaces after the hash", ~S(#   sobelow_skip ["Config.CSRF"])},
          {"no space before the list", ~S(# sobelow_skip["Config.CSRF"])},
          {"several spaces before the list", ~S(# sobelow_skip   ["Config.CSRF"])},
          {"padding inside the list", ~S(# sobelow_skip [ "Config.CSRF" ])},
          {"a space before the comma", ~S(# sobelow_skip ["Config.CSRF" , "Config.CSP"])},
          {"no space after the comma", ~S(# sobelow_skip ["Config.CSRF","Config.CSP"])},
          {"a trailing comma", ~S(# sobelow_skip ["Config.CSRF",])}
        ] do
      test "is tolerated: #{name}" do
        temp_fixture_file("basic", @router_path, router(unquote(comment)))

        refute "Config.CSRF" in finding_modules(scan("basic", skip: true))
      end
    end
  end

  describe "a skip comment that cannot be read" do
    test "warns naming the file and line, rather than being ignored in silence" do
      temp_fixture_file("basic", @router_path, router(~S(# sobelow_skip ['Config.CSRF'])))

      {_stdout, stderr} = scan_io("basic", skip: true)

      assert stderr =~ "#{@router_path}:4: could not read this `# sobelow_skip` comment"
      assert stderr =~ ~S(# sobelow_skip ["Config.CSRF"])
    end

    test "still reports the finding it failed to suppress" do
      temp_fixture_file("basic", @router_path, router(~S(# sobelow_skip ['Config.CSRF'])))

      assert "Config.CSRF" in finding_modules(scan("basic", skip: true))
    end

    test "warns once, not once per read of the file" do
      temp_fixture_file("basic", @router_path, router(~S(# sobelow_skip ['Config.CSRF'])))

      {_stdout, stderr} = scan_io("basic", skip: true)

      warnings =
        stderr
        |> String.split("\n")
        |> Enum.count(&(&1 =~ "could not read this `# sobelow_skip` comment"))

      assert warnings == 1
    end

    test "covers a list broken across several comment lines" do
      router = """
      defmodule BasicWeb.Router do
        use BasicWeb, :router

        # sobelow_skip [
        #   "Config.CSRF"
        # ]
        pipeline :browser do
          plug(:accepts, ["html"])
          plug(:fetch_session)
        end
      end
      """

      temp_fixture_file("basic", @router_path, router)

      {_stdout, stderr} = scan_io("basic", skip: true)

      assert stderr =~ "#{@router_path}:4: could not read this `# sobelow_skip` comment"
    end
  end

  describe "no warning is emitted" do
    test "for a comment that was understood" do
      temp_fixture_file("basic", @router_path, router(~S(# sobelow_skip ["Config.CSRF"])))

      {_stdout, stderr} = scan_io("basic", skip: true)

      refute stderr =~ "could not read"
    end

    # Without `--skip` nothing is rewritten, so every valid comment would look
    # unrecognised.
    test "without --skip, where skip comments are not read at all" do
      temp_fixture_file("basic", @router_path, router(~S(# sobelow_skip ['Config.CSRF'])))

      {_stdout, stderr} = scan_io("basic", skip: false)

      refute stderr =~ "could not read"
    end

    # Requiring the bracket is what keeps prose out of it.
    test "for prose that merely mentions the marker" do
      router = """
      defmodule BasicWeb.Router do
        use BasicWeb, :router

        # Suppress a check on a pipeline with a # sobelow_skip comment.
        pipeline :browser do
          plug(:accepts, ["html"])
          plug(:fetch_session)
        end
      end
      """

      temp_fixture_file("basic", @router_path, router)

      {_stdout, stderr} = scan_io("basic", skip: true)

      refute stderr =~ "could not read"
    end
  end

  # The fixture app reports `Traversal.SendFile` in its controller too, so match
  # on the router specifically.
  defp router_finding?(report, module) do
    report
    |> findings_for(module)
    |> Enum.any?(&String.ends_with?(Map.fetch!(&1, "file"), "router.ex"))
  end
end
