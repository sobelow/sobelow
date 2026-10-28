defmodule SobelowTest.E2E.CompileTest do
  use Sobelow.ScanCase, async: false

  test "grades source separately from file selection and resolves aliases and imports" do
    temp_fixture_file("basic", "lib/basic_web/controllers/compile_controller.ex", """
    defmodule BasicWeb.CompileController do
      use BasicWeb, :controller
      alias Code, as: Compiler
      import Code, only: [require_file: 2]
      def index(conn, %{"source" => source, "root" => root}) do
        Compiler.compile_string(source)
        Compiler.compile_quoted(source)
        Compiler.compile_file(source)
        "startup.exs" |> require_file(root)
        Compiler.compile_string("1 + 2", source)
      end
      # sobelow_skip ["RCE.Compile"]
      def skipped(source), do: Code.compile_string(source)
    end
    defmodule CompileHelper do
      def load(source), do: Code.compile_string(source)
      def load_file(file), do: Code.require_file(file)
    end
    """)

    found = scan("basic", only: ["RCE.Compile"], skip: true) |> findings_for("RCE.Compile")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"]})) ==
             [{6, "high"}, {7, "high"}, {8, "medium"}, {9, "medium"}, {16, "low"}, {17, "low"}]

    assert [] = scan("basic", ignored: ["RCE"]) |> findings_for("RCE.Compile")

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["RCE.Compile"], format: format)
      assert output =~ if(format == "sarif", do: "SBLW043", else: "RCE.Compile")
    end
  end

  test "unrelated Code aliases and excluded imports remain unreported" do
    temp_fixture_file("basic", "lib/unrelated_compilers.ex", """
    defmodule UnrelatedCompilers do
      alias Other.Code
      import Elixir.Code, except: [compile_string: 1]
      def unrelated(source), do: Code.compile_string(source)
      def excluded(source), do: source |> compile_string()
    end
    """)

    assert [] = scan("basic", only: ["RCE.Compile"]) |> findings_for("RCE.Compile")
  end
end
