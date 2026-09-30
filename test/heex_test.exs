defmodule Sobelow.HEExTest do
  use ExUnit.Case, async: true
  alias Sobelow.{HEEx, Parse}

  test "multiple attributes, quoted braces and unicode retain exact AST locations" do
    source = ~S|<div title="}" data={raw(@first)} other={raw(%{value: "}"}.value)}>
    café {raw(@second)}
    </div>|
    ast = HEEx.ast(source, "example.heex", 7)

    {_, calls} =
      Macro.prewalk(ast, [], fn
        {:raw, _, _} = node, calls -> {node, [node | calls]}
        node, calls -> {node, calls}
      end)

    assert Enum.map(Enum.reverse(calls), &{Parse.get_fun_line(&1), Parse.get_fun_column(&1)}) ==
             [{7, 22}, {7, 42}, {8, 11}]
  end

  test "many body and attribute interpolations preserve all expressions in order" do
    source =
      Enum.map_join(1..3000, "\n", fn i ->
        "<span title={raw(@value#{i})}>{raw(@body#{i})}</span>"
      end)

    ast = HEEx.ast(source, "large.heex")

    {_, calls} =
      Macro.prewalk(ast, [], fn
        {:raw, _, _} = node, calls -> {node, [node | calls]}
        node, calls -> {node, calls}
      end)

    assert length(calls) == 6000
    assert Parse.get_fun_line(hd(calls)) == 3000
    assert Parse.get_fun_line(List.last(calls)) == 1
  end
end
