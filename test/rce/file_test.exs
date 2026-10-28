defmodule SobelowTest.RCE.FileTest do
  use ExUnit.Case, async: true
  alias Sobelow.RCE.File, as: FileCheck

  for call <- [
        ":file.eval(file)",
        ":file.eval(file, bindings)",
        ":file.script(file)",
        ":file.script(file, bindings)",
        ":file.path_eval(paths, file)",
        ":file.path_script(paths, file)",
        ":file.path_script(paths, file, bindings)",
        "file |> :file.eval()",
        "file |> :file.eval(bindings)",
        "file |> :file.script(bindings)",
        "paths |> :file.path_eval(file)",
        "paths |> :file.path_script(file, bindings)",
        ~s':file.path_script(paths, ~c"startup.erl")',
        ~s':file.path_eval([~c"config", path], ~c"startup.erl")',
        ":file.script(@filename)",
        "&:file.script/1",
        "&:file.eval/2",
        "&:file.path_script/3",
        "&:file.script(&1)",
        ~S':file.script(~c"#{file}/startup.erl")'
      ] do
    test "one finding for #{call}" do
      ast = Code.string_to_quoted!("def run(file, paths, path, bindings), do: #{unquote(call)}")
      assert {[_], _, _} = FileCheck.parse_def(ast)
    end
  end

  for call <- [
        ~s':file.eval("startup.erl")',
        ~s':file.eval("startup.erl", bindings)',
        ~s':file.script(~c"startup.erl")',
        ~s':file.path_script([~c"config"], ~c"startup.erl", bindings)',
        ~s':file.path_script(paths, "/opt/app/startup.erl", bindings)',
        ~s'paths |> :file.path_eval(~c"/opt/app/startup.erl")',
        ~s':file.path_script(paths, ~C"/opt/app/startup.erl")',
        ":file.path_eval(paths, [47, 955, 46, 101, 114, 108])",
        ~s':file.path_script(paths, :"/opt/app/startup.erl")',
        ~s':file.script(~s"startup.erl")',
        ~s':file.path_script(paths, ~s"/opt/app/startup.erl")',
        ":file.consult(file)",
        ":file.read_file(file)",
        ":other.script(file)",
        "script(file)",
        ":file.script()",
        "&:file.script/0",
        ":file.script(file, bindings, extra)",
        ":file.path_eval(paths, file, bindings)",
        "&:file.path_eval/3",
        ~s'&:file.script("startup.erl", &1)'
      ] do
    test "omits #{call}" do
      ast = Code.string_to_quoted!("def run(file, paths, bindings), do: #{unquote(call)}")
      assert {[], _, _} = FileCheck.parse_def(ast)
    end
  end

  test "keeps the original capture and pipe call metadata" do
    ast = Code.string_to_quoted!("def run(file), do: & :file.script/1")
    assert {[{{:&, _, _} = capture, _}], _, _} = FileCheck.parse_def(ast)
    assert Macro.to_string(capture) == "&:file.script/1"

    ast = Code.string_to_quoted!("def run(file), do: file |> :file.script()")

    assert {[{{{:., _, [:file, :script]}, _, []} = call, [:file]}], _, _} =
             FileCheck.parse_def(ast)

    assert Sobelow.Parse.get_fun_line(call) == 1
  end

  test "merges path variables and extracts charlist interpolation" do
    ast = Code.string_to_quoted!("def run(paths, file), do: :file.path_script(paths, file)")
    assert {[{_, variables}], _, _} = FileCheck.parse_def(ast)
    assert Enum.sort(variables) == [:file, :paths]

    ast = Code.string_to_quoted!(~S'def run(file), do: :file.script(~c"#{file}/run.erl")')
    assert {[{_, [:file]}], _, _} = FileCheck.parse_def(ast)
  end

  test "malformed directory values do not crash the check" do
    ast = Code.string_to_quoted!("def run(paths, file), do: :file.path_script(paths, [file])")
    assert {[_], _, _} = FileCheck.parse_def(ast)
  end
end
