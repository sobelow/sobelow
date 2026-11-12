defmodule SobelowTest.DOS.DecompressionTest do
  use ExUnit.Case, async: true
  alias Sobelow.DOS.Decompression

  for call <- [
        ":zlib.gunzip(data)",
        ":zlib.uncompress(data)",
        ":zlib.unzip(data)",
        ":zlib.inflate(stream, data)",
        ":zlib.inflate(stream, data, exception_on_need_dict: false)",
        "data |> :zlib.gunzip()",
        "data |> :zlib.uncompress",
        "stream |> :zlib.inflate(data)",
        "stream |> :zlib.inflate(data, [])",
        "&:zlib.gunzip/1",
        "&:zlib.uncompress/1",
        "&:zlib.unzip/1",
        "&:zlib.inflate/2",
        "&:zlib.inflate/3",
        "&:zlib.inflate(stream, &1)",
        ":zlib.gunzip(@compressed)",
        ":zlib.gunzip(load_data())",
        ":zlib.uncompress([header, data])",
        ":zlib.inflate(stream, <<header::binary, data::binary>>)",
        ":zlib.gunzip(config.upload[:data])",
        ~S':zlib.gunzip(~s"#{data}")'
      ] do
    test "reports once for #{call}" do
      ast = Code.string_to_quoted!("def read(data, stream), do: #{unquote(call)}")
      assert {[_], _, _} = Decompression.parse_def(ast)
    end
  end

  for call <- [
        ":zlib.gunzip(\"literal data\")",
        ":zlib.uncompress(<<1, 2, 3>>)",
        ":zlib.gunzip(<<1::8, 2::little-32>>)",
        ":zlib.inflate(stream, <<1::integer-signed-size(16)-unit(2)>>)",
        ":zlib.uncompress([<<1::8>>, <<2::16>>])",
        ":zlib.unzip([1, 2, 3])",
        ":zlib.inflate(stream, [])",
        ":zlib.inflate(stream, <<>>)",
        ":zlib.inflate(stream, <<>>, options)",
        "stream |> :zlib.inflate(<<>>, options)",
        ":zlib.safeInflate(stream, data)",
        "&:zlib.safeInflate/2",
        ":zlib.inflateChunk(stream, data)",
        ":zlib.inflateChunk(stream)",
        ":zlib.open()",
        ":zlib.inflateInit(stream)",
        ":zlib.inflateInit(stream, window_bits)",
        ":zlib.inflateReset(stream)",
        ":zlib.inflateEnd(stream)",
        ":zlib.close(stream)",
        ":zlib.gzip(data)",
        ":zlib.compress(data)",
        ":zlib.zip(data)",
        ":zlib.deflate(stream, data)",
        ":other.gunzip(data)",
        ":other.inflate(stream, data)",
        ":zip.unzip(data)",
        "gunzip(data)",
        "inflate(stream, data)",
        ":zlib.gunzip()",
        ":zlib.gunzip(data, extra)",
        ":zlib.inflate(stream)",
        ":zlib.inflate(stream, data, [], extra)",
        "&:zlib.inflate/1",
        "&:zlib.gunzip/2"
      ] do
    test "omits #{call}" do
      ast = Code.string_to_quoted!("def read(data, stream), do: #{unquote(call)}")
      assert {[], _, _} = Decompression.parse_def(ast)
    end
  end

  test "labels compressed input, not stream state or options" do
    ast =
      Code.string_to_quoted!(
        "def read(stream, data, opts), do: :zlib.inflate(stream, data, opts)"
      )

    assert {[{_, [:data]}], [:stream, :data, :opts], {:read, 1}} = Decompression.parse_def(ast)
  end

  test "preserves original piped call nodes and capture locations" do
    for expression <- ["stream |> :zlib.inflate(data, [])", "&:zlib.inflate/2"] do
      ast = Code.string_to_quoted!("def read(stream, data), do: #{expression}")
      assert {[{call, _}], _, _} = Decompression.parse_def(ast)
      {_, nodes} = Macro.prewalk(ast, [], fn node, nodes -> {node, [node | nodes]} end)
      assert call in nodes
      assert Sobelow.Parse.get_fun_line(call) == 1
    end
  end
end
