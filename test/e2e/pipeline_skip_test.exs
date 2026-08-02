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

  # The fixture app reports `Traversal.SendFile` in its controller too, so match
  # on the router specifically.
  defp router_finding?(report, module) do
    report
    |> findings_for(module)
    |> Enum.any?(&String.ends_with?(Map.fetch!(&1, "file"), "router.ex"))
  end
end
