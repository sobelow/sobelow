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
