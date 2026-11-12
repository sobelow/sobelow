defmodule SobelowTest.E2E.ZipTest do
  use Sobelow.ScanCase, async: false

  test "grades archive provenance conservatively and handles stay low confidence" do
    temp_fixture_file("basic", "lib/basic_web/controllers/archive_controller.ex", """
    defmodule BasicWeb.ArchiveController do
      use BasicWeb, :controller
      def index(conn, %{"archive" => archive, "handle" => handle}) do
        :zip.unzip(archive, [:memory])
        archive |> :zip.extract(cwd: ~c"output")
        :zip.unzip(local_archive())
        :zip.zip_get(~c"document.xml", handle)
        :zip.zip_get(handle)
      end
    end
    defmodule ArchiveHelper do
      def read(archive), do: :zip.unzip(archive)
    end
    """)

    found = scan("basic", only: ["DOS.Zip"]) |> findings_for("DOS.Zip")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"]})) ==
             [{4, "medium"}, {5, "medium"}, {6, "low"}, {7, "low"}, {8, "low"}, {12, "low"}]
  end

  test "typed binary inputs retain controller provenance while literal binaries are omitted" do
    temp_fixture_file("basic", "lib/basic_web/controllers/binary_archive_controller.ex", """
    defmodule BasicWeb.BinaryArchiveController do
      use BasicWeb, :controller
      def index(conn, %{"archive" => archive}) do
        :zip.unzip(<<archive::binary>>, [:memory])
        :zip.extract(<<1::8, 2::little-32>>)
        :zip.unzip([<<archive::binary>>, <<1::8>>])
      end
    end
    """)

    found = scan("basic", only: ["DOS.Zip"]) |> findings_for("DOS.Zip")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"], &1["variable"]})) ==
             [{4, "medium", "archive"}, {6, "medium", "archive"}]
  end

  test "metadata prechecks, output checks and custom validators do not hide extraction" do
    temp_fixture_file("basic", "lib/archive_reader.ex", """
    defmodule ArchiveReader do
      def read(archive) do
        {:ok, entries} = :zip.list_dir(archive)
        :ok = check_declared_sizes(entries)
        :ok = check_actual_sizes(archive)
        {:ok, files} = :zip.unzip(archive, [:memory, file_list: [~c"document.xml"]])
        :ok = check_output_size(files)
        files
      end
    end
    """)

    assert [%{"line" => 6, "confidence" => "low"}] =
             scan("basic", only: ["DOS.Zip"]) |> findings_for("DOS.Zip")
  end

  test "resolves explicit Erlang imports, pipes and captures without duplicate findings" do
    temp_fixture_file("basic", "lib/archive_imports.ex", """
    defmodule ArchiveImports do
      import :zip, only: [unzip: 1, extract: 2, zip_get: 2]
      def read(archive), do: unzip(archive)
      def pipe(archive), do: archive |> extract([:memory])
      def capture(archives), do: Enum.map(archives, &unzip/1)
      def inline(handles), do: Enum.map(handles, &zip_get(~c"document.xml", &1))
      def qualified(archive), do: :zip.extract(archive)
    end
    """)

    found = scan("basic", only: ["DOS.Zip"]) |> findings_for("DOS.Zip")
    assert Enum.sort(Enum.map(found, & &1["line"])) == [3, 4, 5, 6, 7]
  end

  test "unrelated imports, local helpers, excluded arities and import scope stay unreported" do
    temp_fixture_file("basic", "lib/unrelated_archives.ex", """
    defmodule UnrelatedArchives do
      import Other, only: [unzip: 1]
      def read(archive), do: unzip(archive)
      def excluded(archive) do
        import :zip, except: [extract: 1]
        extract(archive)
      end
      def wrong_arity(archive) do
        import :zip, only: [extract: 1]
        archive |> extract([:memory])
      end
      def excluded_capture(archives) do
        import :zip, except: [unzip: 1]
        Enum.map(archives, &unzip/1)
      end
    end
    defmodule ArchiveNeighbor do
      def read(archive), do: unzip(archive)
      defp unzip(archive), do: archive
    end
    """)

    assert [] = scan("basic", only: ["DOS.Zip"]) |> findings_for("DOS.Zip")
  end

  test "inline fold content access uses archive provenance and enclosing call locations" do
    temp_fixture_file("basic", "lib/basic_web/controllers/fold_controller.ex", """
    defmodule BasicWeb.FoldController do
      use BasicWeb, :controller
      import :zip, only: [foldl: 3]
      def index(conn, %{"archive" => archive}) do
        foldl(fn _, _, get, acc -> {get.(), get.(), acc} end, [], archive)
        foldl(fn _, _, get, acc -> value = get.(); get = other; {value, acc} end, [], archive)
        :zip.foldl(fn _, info, _, acc -> {info.(), acc} end, [], archive)
      end
      # sobelow_skip ["DOS.Zip"]
      def skipped(archive), do: :zip.foldl(fn _, _, get, acc -> {get.(), acc} end, [], archive)
    end
    """)

    found = scan("basic", only: ["DOS.Zip"], skip: true) |> findings_for("DOS.Zip")

    assert Enum.map(found, &{&1["line"], &1["confidence"], &1["variable"]}) ==
             [{5, "medium", "archive"}, {6, "medium", "archive"}]

    {output, _} = scan_io("basic", only: ["DOS.Zip"], skip: true, format: "sarif")
    assert output =~ "SBLW046"
  end

  test "supports only, category and check ignores, function skips and all output formats" do
    temp_fixture_file("basic", "lib/archive_reader.ex", """
    defmodule ArchiveReader do
      def read(archive), do: :zip.unzip(archive)
      # sobelow_skip ["DOS.Zip"]
      def skipped(handle), do: :zip.zip_get(handle)
    end
    """)

    assert [_, _] = scan("basic", only: ["DOS.Zip"]) |> findings_for("DOS.Zip")
    assert [_] = scan("basic", only: ["DOS.Zip"], skip: true) |> findings_for("DOS.Zip")

    for ignored <- ["DOS.Zip", "DOS"] do
      assert [] = scan("basic", ignored: [ignored]) |> findings_for("DOS.Zip")
    end

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["DOS.Zip"], format: format, skip: true)
      assert output =~ if(format == "sarif", do: "SBLW046", else: "DOS.Zip")
    end

    assert Sobelow.DOS.Zip.rule().name == "DOS.Zip"
    assert Sobelow.DOS.details() =~ "DOS.Zip"
    assert ExUnit.CaptureIO.capture_io(fn -> Mix.Tasks.Help.run(["sobelow"]) end) =~ "DOS.Zip"
  end
end
