defmodule SobelowTest.DOS.CompressedFileTest do
  use ExUnit.Case, async: true
  alias Sobelow.DOS.CompressedFile

  for body <- [
        "{:ok, io} = File.open(path, [:read, :compressed]); IO.binread(io, :all)",
        "io = File.open!(path, [:compressed]); IO.read(io, :eof)",
        "{:ok, io} = :file.open(path, [:read, :compressed_one]); IO.binread(io, :all)",
        "File.open(path, [:compressed], fn io -> IO.binread(io, :all) end)",
        "File.open!(path, [:compressed], fn io -> io |> IO.read(:eof) end)",
        "{:ok, io} = File.open(path, [:compressed]); value = IO.read(io, :all); value",
        "io = path |> File.open!([:compressed]); IO.binread(io, :all)",
        "{:ok, io} = path |> File.open([:compressed]); io |> IO.read(:eof)",
        "{:ok, io} = path |> :file.open([:read, :compressed]); IO.binread(io, :all)",
        "path |> File.open!([:compressed], fn io -> IO.binread(io, :all) end)",
        "io = File.open!(path, [:compressed]); File.open!(other, [:read], fn other_io -> IO.read(other_io, 1) end); IO.binread(io, :all)"
      ] do
    test "connects open and full read in #{body}" do
      ast = Code.string_to_quoted!("def read(path), do: (#{unquote(body)})")
      assert {[{_, [:path]}], [:path], {:read, 1}} = CompressedFile.parse_def(ast)
    end
  end

  for body <- [
        "{:ok, io} = File.open(path, [:compressed]); IO.binread(other, :all)",
        "{:ok, io} = File.open(path, [:read]); IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed, :write]); IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed, :raw]); IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed, mode]); IO.binread(io, :all)",
        "{:ok, io} = File.open(path, modes); IO.binread(io, :all)",
        "{:ok, io} = File.open(\"bundled.gz\", [:compressed]); IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed]); IO.binread(io, 1024)",
        "{:ok, io} = File.open(path, [:compressed]); IO.binread(io, :line)",
        "{:ok, io} = File.open(path, [:compressed]); io = other; IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed]); {io, _} = pair; IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed]); File.close(io); IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed]); :file.close(io); IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed]); transfer(io); IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed]); alias_io = io; IO.binread(alias_io, :all)",
        "{:ok, io} = File.open(path, [:compressed]); Enum.map(items, fn io -> IO.binread(io, :all) end)",
        "{:ok, io} = File.open(path, [:compressed]); if flag, do: IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed]); if flag, do: transfer(io); IO.binread(io, :all)",
        "File.open(path, [:compressed], callback)",
        "File.open(path, [:compressed], fn io -> IO.binread(other, :all) end)",
        "File.open(path, [:compressed], fn io -> io = other; IO.binread(io, :all) end)",
        "{:ok, io} = Other.open(path, [:compressed]); IO.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed]); Other.binread(io, :all)",
        "{:ok, io} = File.open(path, [:compressed]); quote do: IO.binread(io, :all)",
        "io = File.open!(path, [:compressed]); File.open!(other, [:read], fn _ -> File.close(io) end); IO.binread(io, :all)",
        "io = File.open!(path, [:compressed]); File.open!(other, [:compressed], fn _ -> transfer(io) end); IO.binread(io, :all)",
        "io = File.open!(path, [:compressed]); File.open!(\"bundled\", [:read], fn _ -> :file.close(io) end); IO.binread(io, :all)",
        "io = File.open!(path, [:compressed]); other |> File.open!([:read], fn _ -> File.close(io) end); IO.binread(io, :all)",
        "io = File.open!(path, [:compressed]); File.open!(other, [:read], fn _ when flag -> transfer(io) end); IO.binread(io, :all)",
        "io = File.open!(path, [:compressed]); File.open!(other, [:read], &transfer(io, &1)); IO.binread(io, :all)",
        "io = File.open!(path, [:compressed]); File.open!(io, [:read]); IO.binread(io, :all)",
        "io = path |> File.open!([:read]); IO.binread(io, :all)",
        "io = path |> Other.open!([:compressed]); IO.binread(io, :all)"
      ] do
    test "omits unrelated, bounded or unsupported flow #{body}" do
      ast = Code.string_to_quoted!("def read(path), do: (#{unquote(body)})")
      assert {[], _, _} = CompressedFile.parse_def(ast)
    end
  end

  test "preserves the read AST and supports repeated direct reads" do
    ast =
      Code.string_to_quoted!("""
      def read(path) do
        {:ok, io} = File.open(path, [:compressed])
        IO.binread(io, :all)
        IO.binread(io, :all)
      end
      """)

    assert {[{first, [:path]}, {second, [:path]}], _, _} = CompressedFile.parse_def(ast)
    assert Sobelow.Parse.get_fun_line(first) == 3
    assert Sobelow.Parse.get_fun_line(second) == 4
    {_, nodes} = Macro.prewalk(ast, [], fn node, nodes -> {node, [node | nodes]} end)
    assert first in nodes
    assert second in nodes
  end
end
