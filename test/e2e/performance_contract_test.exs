defmodule Sobelow.PerformanceContractTest do
  use Sobelow.ScanCase, async: false

  test "all renders in one function see the same template snapshot" do
    path =
      temp_fixture_file("basic", "lib/basic_web/controllers/repeated_controller.ex", """
      defmodule BasicWeb.RepeatedController do
        use BasicWeb, :controller
        def show(conn, name) do
          render(conn, :show, name: name)
          render(conn, :show, name: name)
        end
      end
      """)

    temp_fixture_file(
      "basic",
      "lib/basic_web/controllers/repeated_html/show.html.heex",
      "{raw(@name)}"
    )

    findings =
      scan("basic")
      |> findings_for("XSS.Raw")
      |> Enum.filter(&String.ends_with?(&1["file"], path))

    assert Enum.map(findings, &{&1["line"], &1["confidence"]}) == [{4, "high"}, {5, "high"}]
  end

  test "a medium render does not consume evidence needed by a later high render" do
    path =
      temp_fixture_file("basic", "lib/basic_web/controllers/shared_controller.ex", """
      defmodule BasicWeb.SharedController do
        use BasicWeb, :controller
        def local(conn), do: render(conn, :show, name: lookup())
        def reflected(conn, name), do: render(conn, :show, name: name, meta: [])
        def nested(conn, name), do: conn |> wrap(render(conn, :show, name: name))
      end
      """)

    temp_fixture_file(
      "basic",
      "lib/basic_web/controllers/shared_html/show.html.heex",
      "{raw(@name)}"
    )

    assert scan("basic", threshold: :high)
           |> findings_for("XSS.Raw")
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(&{&1["line"], &1["variable"]}) == [{4, "@name"}, {5, "@name"}]
  end

  test "template selection retains entries and quietly omits missing paths" do
    scan("basic")
    all = Sobelow.MetaLog.get_templates()
    paths = [hd(Map.keys(all)), "missing.html.heex"]
    assert Sobelow.MetaLog.get_templates(paths) == Map.take(all, paths)
    assert Sobelow.MetaLog.get_templates() == all
  end
end
