defmodule SobelowTest.E2E.CompressedFileTest do
  use Sobelow.ScanCase, async: false

  test "piped alias opens preserve read locations and callbacks invalidate captured devices" do
    temp_fixture_file("basic", "lib/basic_web/controllers/compressed_pipe_controller.ex", """
    defmodule BasicWeb.CompressedPipeController do
      use BasicWeb, :controller
      alias File, as: F
      import IO, only: [binread: 2]
      def index(conn, %{"path" => path, "other" => other}) do
        io = path |> F.open!([:compressed])
        io |> binread(:all)
        F.open!(other, [:read], fn _ -> F.close(io) end)
        binread(io, :all)
      end
    end
    """)

    assert [%{"line" => 7, "confidence" => "medium", "variable" => "path"}] =
             scan("basic", only: ["DOS.CompressedFile"]) |> findings_for("DOS.CompressedFile")
  end

  test "resolves aliases and imports with controller path confidence and normal output" do
    temp_fixture_file("basic", "lib/basic_web/controllers/compressed_file_controller.ex", """
    defmodule BasicWeb.CompressedFileController do
      use BasicWeb, :controller
      alias File, as: F
      import IO, only: [binread: 2]
      def index(conn, %{"path" => path}) do
        {:ok, io} = F.open(path, [:compressed])
        io |> binread(:all)
        F.open!(path, [:compressed], fn device -> binread(device, :eof) end)
      end
      # sobelow_skip ["DOS.CompressedFile"]
      def skipped(path), do: File.open!(path, [:compressed], fn io -> IO.read(io, :all) end)
    end
    defmodule CompressedFileHelper do
      import :file, only: [open: 2]
      def read(path) do
        {:ok, io} = open(path, [:compressed, :read])
        IO.binread(io, :all)
      end
    end
    """)

    found =
      scan("basic", only: ["DOS.CompressedFile"], skip: true)
      |> findings_for("DOS.CompressedFile")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"], &1["variable"]})) ==
             [{7, "medium", "path"}, {8, "medium", "path"}, {17, "low", "path"}]

    for ignored <- ["DOS.CompressedFile", "DOS"] do
      assert [] = scan("basic", ignored: [ignored]) |> findings_for("DOS.CompressedFile")
    end

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["DOS.CompressedFile"], format: format, skip: true)
      assert output =~ if(format == "sarif", do: "SBLW050", else: "DOS.CompressedFile")
    end

    assert Sobelow.get_mod("DOS.CompressedFile") == Sobelow.DOS.CompressedFile
  end
end
