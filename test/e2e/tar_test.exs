defmodule SobelowTest.E2E.TarTest do
  use Sobelow.ScanCase, async: false

  test "grades archive input and resolves imports, pipes, captures and skips" do
    temp_fixture_file("basic", "lib/basic_web/controllers/tar_controller.ex", """
    defmodule BasicWeb.TarController do
      use BasicWeb, :controller
      import :erl_tar, only: [extract: 2]
      def index(conn, %{"data" => data}) do
        :erl_tar.extract({:binary, data}, [:memory, :compressed])
        data |> extract([:memory])
        :erl_tar.extract(local_archive())
      end
      # sobelow_skip ["DOS.Tar"]
      def skipped(data), do: :erl_tar.extract(data)
    end
    defmodule TarHelper do
      def read(data), do: :erl_tar.extract(data)
      def capture, do: &:erl_tar.extract/2
      def literal, do: :erl_tar.extract("bundled.tar")
    end
    """)

    found = scan("basic", only: ["DOS.Tar"], skip: true) |> findings_for("DOS.Tar")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"]})) ==
             [{5, "medium"}, {6, "medium"}, {7, "low"}, {13, "low"}, {14, "low"}]

    for ignored <- ["DOS.Tar", "DOS"] do
      assert [] = scan("basic", ignored: [ignored]) |> findings_for("DOS.Tar")
    end

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["DOS.Tar"], format: format)
      assert output =~ if(format == "sarif", do: "SBLW048", else: "DOS.Tar")
    end

    assert Sobelow.get_mod("DOS.Tar") == Sobelow.DOS.Tar
    assert Sobelow.DOS.details() =~ "DOS.Tar"
  end

  test "omits excluded imports and unrelated operations" do
    temp_fixture_file("basic", "lib/tar_metadata.ex", """
    defmodule TarMetadata do
      import :erl_tar, only: [table: 1]
      def read(data) do
        extract(data)
        table(data)
        :other.extract(data)
      end
    end
    """)

    assert [] = scan("basic", only: ["DOS.Tar"]) |> findings_for("DOS.Tar")
  end
end
