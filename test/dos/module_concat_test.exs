defmodule SobelowTest.DOS.ModuleConcatTest do
  use ExUnit.Case, async: true
  alias Sobelow.DOS.ModuleConcat

  for call <- [
        "Module.concat(names)",
        "Module.concat([App, name])",
        "Module.concat(App, name)",
        "Module.concat(name, Other)",
        "names |> Module.concat()",
        "App |> Module.concat(name)",
        "&Module.concat/1",
        "&Module.concat/2",
        "&Module.concat(App, &1)",
        "Module.concat(@namespace, name)",
        ~S'Module.concat(App, ~s"#{name}")',
        ~S'Module.concat(App, ~c"#{name}")'
      ] do
    test "reports #{call}" do
      ast = Code.string_to_quoted!("def run(names, name), do: #{unquote(call)}")
      assert {[_], _, _} = ModuleConcat.parse_def(ast)
    end
  end

  for call <- [
        "Module.concat([App, Other])",
        "Module.concat(App, Other)",
        "Module.concat([__MODULE__, \"Known\"])",
        "Module.concat([__MODULE__.Known, \"Nested\"])",
        ~S'Module.concat(App, ~s"Known")',
        ~S'Module.concat(App, ~S"Known")',
        "Module.safe_concat(App, name)",
        "Other.concat(App, name)",
        "concat(App, name)",
        "Module.concat()",
        "Module.concat(App, name, extra)"
      ] do
    test "omits #{call}" do
      ast = Code.string_to_quoted!("def run(names, name), do: #{unquote(call)}")
      assert {[], _, _} = ModuleConcat.parse_def(ast)
    end
  end

  test "literal list members do not appear as tainted variable labels" do
    ast = Code.string_to_quoted!("def run(name), do: Module.concat([App, name])")
    assert {[{_, [:name]}], [:name], _} = ModuleConcat.parse_def(ast)
  end

  test "the current module is literal even when a neighboring name is dynamic" do
    for call <- ["Module.concat([__MODULE__, name])", "Module.concat(__MODULE__, name)"] do
      ast = Code.string_to_quoted!("def run(name), do: #{call}")
      assert {[{_, [:name]}], [:name], _} = ModuleConcat.parse_def(ast)
    end
  end
end
