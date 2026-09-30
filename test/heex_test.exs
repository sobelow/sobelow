defmodule Sobelow.HEExTest do
  use ExUnit.Case, async: true
  alias Sobelow.{HEEx, Parse}

  for {kind, attribute} <- [
        {"double quoted", ~S|title=" phx-no-curly-interpolation "|},
        {"single quoted", ~S|title=' phx-no-curly-interpolation '|},
        {"attribute value after equals", ~S|title = " phx-no-curly-interpolation "|},
        {"expression", ~S|title={" phx-no-curly-interpolation "}|},
        {"expression with quotes", ~S|title={"\" phx-no-curly-interpolation \""}|},
        {"different name", ~S|data-phx-no-curly-interpolation="true"|}
      ] do
    test "#{kind} attribute content cannot disable body interpolation" do
      source = "<div #{unquote(attribute)}>{raw(@name)}</div>"
      ast = HEEx.ast(source, "attribute.heex")
      assert [raw] = Parse.get_meta_template_fun(ast).raw
      assert Parse.get_fun_line(raw) == 1
      assert Parse.get_fun_column(raw) == String.length("<div #{unquote(attribute)}>{") + 1
    end
  end

  test "only real disable attributes suppress nested body expressions" do
    source = ~S|<div title=" phx-no-curly-interpolation " phx-no-curly-interpolation>
    <span>{raw(@disabled)}</span>
    </div>
    <div title={" phx-no-curly-interpolation "}>{raw(@enabled)}</div>|

    assert [raw] =
             source
             |> HEEx.ast("attribute.heex")
             |> Parse.get_meta_template_fun()
             |> Map.fetch!(:raw)

    assert Parse.get_fun_line(raw) == 4
  end

  test "real disable attributes after expressions and across lines keep their scope" do
    source = ~S|<section title={" phx-no-curly-interpolation "}
      phx-no-curly-interpolation={false}>
      {raw(@disabled)}
      <span>{raw(@nested)}</span>
    </section>
    <span>{raw(@enabled)}</span>|

    assert [raw] =
             source
             |> HEEx.ast("attribute.heex")
             |> Parse.get_meta_template_fun()
             |> Map.fetch!(:raw)

    assert Parse.get_fun_line(raw) == 6
  end

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

  test "HTML comments cannot disable interpolation after the comment" do
    source =
      "<!-- <div phx-no-curly-interpolation> {raw(@comment)} -->\n<span>{raw(@input)}</span>"

    assert [raw] =
             source
             |> HEEx.ast("comment.heex")
             |> Parse.get_meta_template_fun()
             |> Map.fetch!(:raw)

    assert Parse.get_fun_line(raw) == 2
    assert Parse.get_fun_column(raw) == 8
  end

  for tag <- ["script", "style"] do
    test "#{tag} text cannot be interpreted as HTML attributes or closing ancestor tags" do
      source = """
      <div>
        <#{unquote(tag)}>
          "<span data={1 +}>"
          "</div>{raw(@text)}"
        </#{unquote(tag)}>
        <span>{raw(@input)}</span>
      </div>
      """

      assert [raw] =
               source
               |> HEEx.ast("text.heex")
               |> Parse.get_meta_template_fun()
               |> Map.fetch!(:raw)

      assert Parse.get_fun_line(raw) == 6
      assert Parse.get_fun_column(raw) == 10
    end
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
