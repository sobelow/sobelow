defmodule SobelowTest.Config.HeadersTest do
  use ExUnit.Case
  alias Sobelow.Config

  test "checks normal router for secure headers" do
    router = "./test/fixtures/headers/good_router.ex"

    refute Config.get_pipelines(router)
           |> Enum.any?(&Config.vuln_pipeline?(&1, :headers))
  end

  test "checks normal router for secure headers with additional headers" do
    router = "./test/fixtures/headers/good_router_with_headers.ex"

    refute Config.get_pipelines(router)
           |> Enum.any?(&Config.vuln_pipeline?(&1, :headers))
  end

  test "checks bad router without secure headers" do
    router = "./test/fixtures/headers/bad_router.ex"

    assert Config.get_pipelines(router)
           |> Enum.any?(&Config.vuln_pipeline?(&1, :headers))
  end

  test "honors sobelow_skip on vulnerable pipelines" do
    Application.put_env(:sobelow, :skip, true)
    on_exit(fn -> Application.delete_env(:sobelow, :skip) end)

    router = "./test/fixtures/headers/skipped_router.ex"

    vulnerable =
      Config.get_unskipped_pipelines(router, Sobelow.Config.Headers)
      |> Enum.filter(&Config.vuln_pipeline?(&1, :headers))

    # :browser is skipped, :other is not
    assert [{:pipeline, _, [:other, _]}] = vulnerable
  end

  test "does not honor sobelow_skip when skip flag is disabled" do
    Application.put_env(:sobelow, :skip, false)
    on_exit(fn -> Application.delete_env(:sobelow, :skip) end)

    router = "./test/fixtures/headers/skipped_router.ex"

    vulnerable =
      Config.get_unskipped_pipelines(router, Sobelow.Config.Headers)
      |> Enum.filter(&Config.vuln_pipeline?(&1, :headers))

    assert length(vulnerable) == 2
    assert Enum.find(vulnerable, &match?({:pipeline, _, [:browser, _]}, &1))
    assert Enum.find(vulnerable, &match?({:pipeline, _, [:other, _]}, &1))
  end
end
