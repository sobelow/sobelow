defmodule SobelowTest.RCE.CompileTest do
  use ExUnit.Case, async: true
  alias Sobelow.RCE.Compile

  for source <- [
        "Code.compile_string(input)",
        "Code.compile_string(input, file)",
        "Code.compile_quoted(input)",
        "Code.compile_quoted(input, file)",
        "Code.compile_file(input)",
        "Code.compile_file(input, root)",
        "Code.require_file(input)",
        ~S'Code.require_file("source.exs", root)',
        "input |> Code.compile_string()",
        "input |> Code.compile_file(root)",
        "&Code.require_file/2",
        "&Code.compile_string(&1)",
        "Code.compile_string(@source)",
        ~S'Code.compile_file(~s"#{input}/source.exs")'
      ] do
    test "reports #{source}" do
      ast = Code.string_to_quoted!("def run(input, file, root), do: #{unquote(source)}")
      assert {[_], _, _} = Compile.parse_def(ast)
    end
  end

  for source <- [
        ~S'Code.compile_string("1 + 2", file)',
        ~S'Code.compile_string(~s"1 + 2")',
        "Code.compile_quoted({:literal, [], []}, file)",
        ~S'Code.compile_file("source.exs")',
        ~S'Code.require_file("source.exs", "/opt/app")',
        ~S'Code.require_file("/opt/app/source.exs", root)',
        "Code.eval_string(input)",
        "Other.compile_string(input)",
        "compile_string(input)",
        "Code.compile_string()",
        "Code.compile_string(input, file, extra)"
      ] do
    test "omits #{source}" do
      ast = Code.string_to_quoted!("def run(input, file, root), do: #{unquote(source)}")
      assert {[], _, _} = Compile.parse_def(ast)
    end
  end
end
