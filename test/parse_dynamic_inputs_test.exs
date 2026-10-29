defmodule Sobelow.ParseDynamicInputsTest do
  use ExUnit.Case, async: true
  alias Sobelow.Parse

  test "interpolated string sigils retain their input variables and original call AST" do
    ast = Code.string_to_quoted!(~S'def run(input), do: String.to_atom(~s(prefix_#{input}))')
    [original] = Parse.get_aliased_funs_of_type(ast, :to_atom, [:String])

    assert {[{^original, [:input]}], [:input], {:run, 1}} =
             Parse.get_fun_vars_and_meta(ast, 0, :to_atom, [:String])
  end

  test "literal and escaped string sigils remain untainted" do
    for call <- [~S'String.to_atom(~s(literal))', ~S'String.to_atom(~s(\#{literal}))'] do
      ast = Code.string_to_quoted!("def run(input), do: #{call}")
      assert {[], [:input], {:run, 1}} = Parse.get_fun_vars_and_meta(ast, 0, :to_atom, [:String])
    end
  end

  test "piped capture placeholders retain their argument number and original sink AST" do
    ast = Code.string_to_quoted!("def run(inputs), do: Enum.map(inputs, &(&1 |> :os.cmd()))")
    [original] = Parse.get_erlang_aliased_funs_of_type(ast, :cmd, :os)

    assert {[{^original, ["&1"]}], [:inputs], {:run, 1}} =
             Parse.get_erlang_fun_vars_and_meta(ast, 0, :cmd, :os)

    assert Parse.extract_opts(Code.string_to_quoted!("&2")) == "&2"
  end

  for {access, labels} <- [
        {"config.prefix[:key]", ["config.prefix"]},
        {"config.nested.prefix[:key]", ["config.nested.prefix"]},
        {"config[:key][:other]", [:config]},
        {"provider.()[:key]", ["provider.()"]},
        {~s|conn.params["nested"]["name"]|, ["conn.params"]}
      ] do
    test "bracket access labels stay printable across checks: #{access}" do
      access = unquote(access)
      labels = unquote(labels)
      assert Parse.dynamic_vars(Code.string_to_quoted!(access)) == labels

      for expression <- [access, ~s|"\#{#{access}}\#{name}"|] do
        expected = if expression == access, do: labels, else: Enum.uniq(labels ++ [:name])

        for {check, call} <- [
              {Sobelow.DOS.ModuleConcat, "Module.concat([#{expression}, Client])"},
              {Sobelow.DOS.StringToAtom, "String.to_atom(#{expression})"},
              {Sobelow.RCE.Compile, "Code.compile_string(#{expression})"},
              {Sobelow.RCE.Compile, "Code.compile_file(#{expression})"},
              {Sobelow.DOS.Consult, ":file.consult(#{expression})"},
              {Sobelow.RCE.File, ":file.eval(#{expression})"}
            ] do
          ast =
            Code.string_to_quoted!("def run(conn, config, name, provider), do: #{call}",
              columns: true
            )

          {:def, _, [_head, [do: original]]} = ast
          parsed = check.parse_def(ast)
          assert {[{^original, variables}], _, _} = parsed
          assert List.wrap(variables) == expected

          assert Sobelow.FunctionAnalysis.with_fun(ast, fn -> check.parse_def(ast) end) == parsed

          assert [finding] =
                   Sobelow.Finding.init("Test.Check: Bracket access", "brackets.ex")
                   |> Sobelow.Finding.multi_from_def(ast, parsed)

          assert finding.vuln_variable ==
                   if(length(expected) == 1, do: hd(expected), else: Enum.join(expected, " and "))

          assert finding.vuln_source == original
          assert finding.vuln_line_no == Parse.get_fun_line(original)
          assert finding.vuln_col_no == Parse.get_fun_column(original)

          assert finding.confidence ==
                   if(Enum.any?(expected, &(&1 in [:config, :name, "conn.params"])),
                     do: :high,
                     else: :medium
                   )
        end
      end
    end
  end

  test "cached traversal retains piped capture placeholders" do
    ast = Code.string_to_quoted!("def run(inputs), do: Enum.map(inputs, &(&1 |> :os.cmd()))")

    assert Sobelow.FunctionAnalysis.with_fun(ast, fn ->
             Parse.get_erlang_fun_vars_and_meta(ast, 0, :cmd, :os)
           end) == Parse.get_erlang_fun_vars_and_meta(ast, 0, :cmd, :os)

    assert {[_], _, _} =
             Sobelow.FunctionAnalysis.with_fun(ast, fn ->
               Parse.get_erlang_fun_vars_and_meta(ast, 0, :cmd, :os)
             end)
  end
end
