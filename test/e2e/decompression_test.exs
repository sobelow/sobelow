defmodule SobelowTest.E2E.DecompressionTest do
  use Sobelow.ScanCase, async: false

  test "grades compressed inputs, not stream state or options" do
    temp_fixture_file("basic", "lib/basic_web/controllers/compression_controller.ex", """
    defmodule BasicWeb.CompressionController do
      use BasicWeb, :controller
      def index(conn, %{"data" => data, "stream" => stream, "opts" => opts}) do
        :zlib.gunzip(data)
        :zlib.uncompress(conn.params["compressed"])
        :zlib.unzip(local_data())
        :zlib.inflate(stream, data)
        stream |> :zlib.inflate(data, opts)
        :zlib.inflate(stream, <<>>, opts)
      end
    end
    defmodule CompressionHelper do
      def read(data), do: :zlib.gunzip(data)
    end
    """)

    found = scan("basic", only: ["DOS.Decompression"]) |> findings_for("DOS.Decompression")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"]})) ==
             [{4, "medium"}, {5, "medium"}, {6, "low"}, {7, "medium"}, {8, "medium"}, {13, "low"}]
  end

  test "typed binary inputs retain controller provenance while literal binaries are omitted" do
    temp_fixture_file("basic", "lib/basic_web/controllers/binary_compression_controller.ex", """
    defmodule BasicWeb.BinaryCompressionController do
      use BasicWeb, :controller
      def index(conn, %{"data" => data, "stream" => stream}) do
        :zlib.gunzip(<<data::binary>>)
        :zlib.inflate(stream, <<1::8, 2::little-32>>)
        :zlib.inflate(stream, [<<data::binary>>, <<1::8>>])
      end
    end
    """)

    found = scan("basic", only: ["DOS.Decompression"]) |> findings_for("DOS.Decompression")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"], &1["variable"]})) ==
             [{4, "medium", "data"}, {6, "medium", "data"}]
  end

  test "input chunking, postchecks and nearby safeInflate do not hide unbounded calls" do
    temp_fixture_file("basic", "lib/compression_reader.ex", """
    defmodule CompressionReader do
      def read(stream, chunks, data) do
        :zlib.safeInflate(stream, data)
        for chunk <- chunks do
          output = :zlib.inflate(stream, chunk)
          check_output_size(output)
        end
        :zlib.gunzip(data)
      end
    end
    """)

    found = scan("basic", only: ["DOS.Decompression"]) |> findings_for("DOS.Decompression")
    assert Enum.sort(Enum.map(found, & &1["line"])) == [5, 8]
  end

  test "resolves Erlang imports, pipes and captures without duplicate findings" do
    temp_fixture_file("basic", "lib/compression_imports.ex", """
    defmodule CompressionImports do
      import :zlib, only: [gunzip: 1, inflate: 2, uncompress: 1]
      def read(data), do: gunzip(data)
      def pipe(stream, data), do: stream |> inflate(data)
      def capture(inputs), do: Enum.map(inputs, &uncompress/1)
      def inline(inputs, stream), do: Enum.map(inputs, &inflate(stream, &1))
      def qualified(data), do: :zlib.unzip(data)
    end
    """)

    found = scan("basic", only: ["DOS.Decompression"]) |> findings_for("DOS.Decompression")
    assert Enum.sort(Enum.map(found, & &1["line"])) == [3, 4, 5, 6, 7]
  end

  test "literal data, compression, bounded primitives and unrelated calls stay unreported" do
    temp_fixture_file("basic", "lib/unrelated_compression.ex", """
    defmodule UnrelatedCompression do
      import Other, only: [gunzip: 1]
      def read(data), do: gunzip(data)
      def excluded(data) do
        import :zlib, except: [uncompress: 1]
        uncompress(data)
      end
      def wrong_arity(stream, data) do
        import :zlib, only: [inflate: 2]
        stream |> inflate(data, [])
      end
      def excluded_capture(inputs) do
        import :zlib, except: [gunzip: 1]
        Enum.map(inputs, &gunzip/1)
      end
      def bounded(stream, data), do: :zlib.safeInflate(stream, data)
      def compress(data), do: :zlib.gzip(data)
      def literal(stream, opts), do: :zlib.inflate(stream, <<1, 2>>, opts)
    end
    defmodule CompressionNeighbor do
      def read(data), do: gunzip(data)
      defp gunzip(data), do: data
    end
    """)

    assert [] = scan("basic", only: ["DOS.Decompression"]) |> findings_for("DOS.Decompression")
  end

  test "supports only, category and check ignores, function skips and all output formats" do
    temp_fixture_file("basic", "lib/compression_reader.ex", """
    defmodule CompressionReader do
      def read(data), do: :zlib.gunzip(data)
      # sobelow_skip ["DOS.Decompression"]
      def skipped(stream, data), do: :zlib.inflate(stream, data)
    end
    """)

    assert [_, _] =
             scan("basic", only: ["DOS.Decompression"]) |> findings_for("DOS.Decompression")

    assert [_] =
             scan("basic", only: ["DOS.Decompression"], skip: true)
             |> findings_for("DOS.Decompression")

    for ignored <- ["DOS.Decompression", "DOS"] do
      assert [] = scan("basic", ignored: [ignored]) |> findings_for("DOS.Decompression")
    end

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["DOS.Decompression"], format: format, skip: true)
      assert output =~ if(format == "sarif", do: "SBLW047", else: "DOS.Decompression")
    end

    assert Sobelow.DOS.Decompression.rule().name == "DOS.Decompression"
    assert Sobelow.DOS.details() =~ "DOS.Decompression"

    assert ExUnit.CaptureIO.capture_io(fn -> Mix.Tasks.Help.run(["sobelow"]) end) =~
             "DOS.Decompression"
  end

  test "ZIP extraction and raw DEFLATE decompression retain separate rule identities" do
    temp_fixture_file("basic", "lib/extraction.ex", """
    defmodule Extraction do
      def archive(data), do: :zip.unzip(data, [:memory])
      def deflate(data), do: :zlib.unzip(data)
    end
    """)

    report = scan("basic", only: ["DOS.Zip", "DOS.Decompression"])
    assert [%{"line" => 2}] = findings_for(report, "DOS.Zip")
    assert [%{"line" => 3}] = findings_for(report, "DOS.Decompression")
  end
end
