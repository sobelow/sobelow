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

  test "template selection retains entries and quietly omits missing paths" do
    scan("basic")
    all = Sobelow.MetaLog.get_templates()
    paths = [hd(Map.keys(all)), "missing.html.heex"]
    assert Sobelow.MetaLog.get_templates(paths) == Map.take(all, paths)
    assert Sobelow.MetaLog.get_templates() == all
  end
end
