defmodule SobelowTest.DOS.ZipTest do
  use ExUnit.Case, async: true
  alias Sobelow.DOS.Zip

  for call <- [
        ":zip.unzip(archive)",
        ":zip.unzip(archive, [:memory])",
        ":zip.extract(archive)",
        ":zip.extract(archive, cwd: destination)",
        "archive |> :zip.unzip()",
        "archive |> :zip.extract([:memory])",
        "archive |> :zip.unzip",
        ":zip.unzip(archive, file_list: [~c\"document.xml\"])",
        ":zip.unzip(archive, file_filter: &accept_entry/1)",
        ":zip.zip_get(handle)",
        ":zip.zip_get(~c\"document.xml\", handle)",
        "handle |> :zip.zip_get()",
        "~c\"document.xml\" |> :zip.zip_get(handle)",
        "&:zip.unzip/1",
        "&:zip.extract/2",
        "&:zip.zip_get/1",
        "&:zip.zip_get/2",
        "&:zip.unzip(&1, [:memory])",
        "&:zip.zip_get(~c\"document.xml\", &1)",
        ":zip.unzip(@archive)",
        ":zip.unzip(load_archive())",
        ~S':zip.extract(~c"#{archive}/upload.zip")',
        ~S':zip.unzip(config.upload[:path])'
      ] do
    test "reports once for #{call}" do
      ast = Code.string_to_quoted!("def read(archive, handle, destination), do: #{unquote(call)}")
      assert {[_], _, _} = Zip.parse_def(ast)
    end
  end

  for call <- [
        ":zip.unzip(<<1, 2, 3>>, [:memory])",
        ":zip.unzip(<<1::8, 2::little-32>>, [:memory])",
        ":zip.extract(<<1::integer-signed-size(16)-unit(2)>>)",
        ":zip.extract(<<1.0::float-64>>)",
        ":zip.unzip(<<\"bundled.zip\"::binary>>)",
        ":zip.unzip(\"bundled.zip\")",
        ":zip.extract(~c\"bundled.zip\", cwd: destination)",
        "~c\"bundled.zip\" |> :zip.unzip([:memory])",
        ":zip.list_dir(archive)",
        ":zip.zip_list_dir(handle)",
        ":zip.zip_get_crc32(name, handle)",
        ":zip.zip_open(archive, [:memory])",
        ":zip.zip_close(handle)",
        ":zip.create(name, files)",
        ":zip.zip(name, files)",
        ":zip.foldl(callback, acc, archive)",
        ":other.unzip(archive)",
        ":other.extract(archive)",
        "unzip(archive)",
        "extract(archive)",
        "zip_get(handle)",
        ":zip.unzip()",
        ":zip.extract(archive, [], extra)",
        ":zip.zip_get()",
        ":zip.zip_get(name, handle, extra)",
        "&:zip.unzip/0",
        "&:zip.extract/3"
      ] do
    test "omits #{call}" do
      ast = Code.string_to_quoted!("def read(archive, handle, destination), do: #{unquote(call)}")
      assert {[], _, _} = Zip.parse_def(ast)
    end
  end

  test "tracks the archive handle, not the selected filename" do
    ast = Code.string_to_quoted!("def read(name, handle), do: :zip.zip_get(name, handle)")
    assert {[{_, [:handle]}], [:name, :handle], {:read, 1}} = Zip.parse_def(ast)
  end

  test "preserves original piped call nodes and capture locations" do
    for expression <- ["archive |> :zip.unzip([:memory])", "&:zip.unzip/1"] do
      ast = Code.string_to_quoted!("def read(archive), do: #{expression}")
      assert {[{call, _}], _, _} = Zip.parse_def(ast)
      {_, nodes} = Macro.prewalk(ast, [], fn node, nodes -> {node, [node | nodes]} end)
      assert call in nodes
      assert Sobelow.Parse.get_fun_line(call) == 1
    end
  end
end
