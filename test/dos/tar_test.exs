defmodule SobelowTest.DOS.TarTest do
  use ExUnit.Case, async: true
  alias Sobelow.DOS.Tar

  for call <- [
        ":erl_tar.extract(archive)",
        ":erl_tar.extract(archive, [:memory, :compressed])",
        ":erl_tar.extract({:binary, data}, [:compressed])",
        ":erl_tar.extract({:file, device}, [])",
        ":erl_tar.extract(archive, files: names, cwd: destination)",
        ":erl_tar.extract(archive, max_size: 1_000)",
        "archive |> :erl_tar.extract([:memory])",
        "&:erl_tar.extract/1",
        "&:erl_tar.extract/2"
      ] do
    test "reports #{call}" do
      ast = Code.string_to_quoted!("def read(archive, data, device), do: #{unquote(call)}")
      assert {[_], _, _} = Tar.parse_def(ast)
    end
  end

  for call <- [
        ":erl_tar.extract(\"bundled.tar\")",
        ":erl_tar.extract({:binary, <<1::8, 2::little-32>>}, [:memory])",
        ":erl_tar.table(archive, [:compressed])",
        ":erl_tar.open(archive, [:read])",
        ":erl_tar.create(archive, files)",
        ":other.extract(archive)",
        "extract(archive)",
        ":erl_tar.extract()",
        ":erl_tar.extract(archive, [], extra)"
      ] do
    test "omits #{call}" do
      ast = Code.string_to_quoted!("def read(archive), do: #{unquote(call)}")
      assert {[], _, _} = Tar.parse_def(ast)
    end
  end

  test "retains binary input labels and original ASTs" do
    ast =
      Code.string_to_quoted!("def read(data), do: :erl_tar.extract({:binary, data}, [:memory])")

    assert {[{call, [:data]}], [:data], {:read, 1}} = Tar.parse_def(ast)
    {_, nodes} = Macro.prewalk(ast, [], fn node, nodes -> {node, [node | nodes]} end)
    assert call in nodes
  end
end
