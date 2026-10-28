defmodule SobelowTest.E2E.ModuleConcatTest do
  use Sobelow.ScanCase, async: false

  test "resolves module aliases and imports, grades parameters and honors skips" do
    temp_fixture_file("basic", "lib/basic_web/controllers/module_controller.ex", """
    defmodule BasicWeb.ModuleController do
      use BasicWeb, :controller
      alias Module, as: Names
      import Module, only: [concat: 2]
      def index(conn, %{"name" => name}) do
        Names.concat(App, name)
        App |> concat(name)
        Module.concat(@namespace)
      end
      # sobelow_skip ["DOS.ModuleConcat"]
      def skipped(name), do: Module.concat(App, name)
    end
    defmodule ModuleHelper do
      def choose(name), do: Module.concat(App, name)
    end
    """)

    found =
      scan("basic", only: ["DOS.ModuleConcat"], skip: true) |> findings_for("DOS.ModuleConcat")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"]})) ==
             [{6, "high"}, {7, "high"}, {8, "medium"}, {14, "low"}]

    assert [] = scan("basic", ignored: ["DOS"]) |> findings_for("DOS.ModuleConcat")

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["DOS.ModuleConcat"], format: format)
      assert output =~ if(format == "sarif", do: "SBLW042", else: "DOS.ModuleConcat")
    end
  end

  test "unrelated aliases and excluded import arities stay unreported" do
    temp_fixture_file("basic", "lib/unrelated_module_names.ex", """
    defmodule UnrelatedModuleNames do
      alias Other.Module
      import Elixir.Module, only: [concat: 1]
      def unrelated(name), do: Module.concat(App, name)
      def wrong_arity(name), do: App |> concat(name)
    end
    """)

    assert [] = scan("basic", only: ["DOS.ModuleConcat"]) |> findings_for("DOS.ModuleConcat")
  end
end
