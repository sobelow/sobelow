defmodule SobelowTest.DOS.ConsultTest do
  use ExUnit.Case, async: true
  alias Sobelow.DOS.Consult

  for call <- [
        ":file.consult(file)",
        "file |> :file.consult()",
        ":file.path_consult(paths, file)",
        ":file.path_consult(paths, ~c\"settings.config\")",
        ":file.path_consult([~c\"config\"], file)",
        "paths |> :file.path_consult(file)",
        "paths |> :file.path_consult(~c\"settings.config\")",
        ":file.path_consult([path], ~c\"settings.config\")",
        "&:file.consult/1",
        "&:file.path_consult/2",
        "&:file.consult(&1)"
      ] do
    test "reports once for #{call}" do
      ast = Code.string_to_quoted!("def read(file, paths, path), do: #{unquote(call)}")
      assert {[_], _, _} = Consult.parse_def(ast)
    end
  end

  test "tracks variables inside interpolated charlists and mixed search paths" do
    for call <- [
          ~S':file.consult(~c"#{file}/settings.config")',
          ~S'~c"#{file}/settings.config" |> :file.consult()',
          ~S':file.path_consult([~c"config", file], ~c"settings.config")'
        ] do
      ast = Code.string_to_quoted!("def read(file), do: #{call}")
      assert {[{_, [:file]}], _, _} = Consult.parse_def(ast)
    end
  end

  for call <- [
        ~S|:file.consult('#{file}/settings.config')|,
        ~S"'#{file}/settings.config' |> :file.consult()",
        ~S|:file.path_consult(['config'], '#{file}/settings.config')|,
        ~S|:file.path_consult(['#{file}/config'], 'settings.config')|,
        ~S"['#{file}/config'] |> :file.path_consult('settings.config')"
      ] do
    test "tracks interpolation and preserves the original call in #{call}" do
      ast = Code.string_to_quoted!("def read(file), do: #{unquote(call)}")
      original_calls = Sobelow.Parse.get_erlang_aliased_funs_of_type(ast, :consult, :file)

      original_calls =
        original_calls ++ Sobelow.Parse.get_erlang_aliased_funs_of_type(ast, :path_consult, :file)

      assert {[{call, [:file]}], [:file], {:read, 1}} = Consult.parse_def(ast)
      assert call in original_calls
    end
  end

  for call <- [
        ":file.consult(\"settings.config\")",
        ":file.consult('settings.config')",
        "'settings.config' |> :file.consult()",
        ":file.path_consult(['config'], 'settings.config')",
        ":file.path_consult(paths, \"/etc/settings.config\")",
        ":file.path_consult(paths, '/etc/settings.config')",
        "paths |> :file.path_consult(\"/etc/settings.config\")",
        ~s':file.consult(~c"settings.config")',
        ~s'~c"settings.config" |> :file.consult()',
        ~s':file.path_consult([~c"config"], ~c"settings.config")',
        ~s':file.path_consult(paths, ~c"/etc/settings.config")',
        ~s'paths |> :file.path_consult(~c"/etc/settings.config")',
        ":other.consult(file)",
        "consult(file)",
        ":file.read_file(file)",
        ":file.eval(file)",
        ":file.consult(file, extra)",
        ":file.path_consult(file)"
      ] do
    test "omits #{call}" do
      ast = Code.string_to_quoted!("def read(file, paths), do: #{unquote(call)}")
      assert {[], _, _} = Consult.parse_def(ast)
    end
  end
end
