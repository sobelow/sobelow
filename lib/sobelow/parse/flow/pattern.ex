defmodule Sobelow.Parse.Flow.Pattern do
  @moduledoc false
  alias Sobelow.Parse.Flow.Value

  def supported?({name, _, nil}) when is_atom(name), do: true
  def supported?({a, b}), do: supported?(a) and supported?(b)
  def supported?({:{}, _, parts}), do: Enum.all?(parts, &supported?/1)
  def supported?({:=, _, [left, right]}), do: supported?(left) and supported?(right)

  def supported?({:%{}, _, fields}) do
    Enum.all?(fields, fn field -> Value.literal_entry?(field) and supported?(elem(field, 1)) end)
  end

  def supported?(term), do: is_atom(term) or is_binary(term) or is_number(term)

  def bind({:when, _, [pattern | _]}, value, env), do: bind(pattern, value, env)
  def bind({:=, _, [left, right]}, value, env), do: bind(right, value, bind(left, value, env))

  def bind({name, meta, nil}, value, env) when is_atom(name) and name != :_,
    do: Map.put(env, name, {meta, value})

  def bind({:%{}, _, fields}, value, env) do
    Enum.reduce(fields, env, fn
      {key, pattern}, acc -> bind(pattern, Value.field(value, key), acc)
      _, acc -> acc
    end)
  end

  def bind({a, b}, value, env), do: bind({:{}, [], [a, b]}, value, env)

  def bind({:{}, _, parts}, value, env) do
    parts
    |> Enum.with_index()
    |> Enum.reduce(env, fn {pattern, i}, acc ->
      bind(pattern, Value.field(value, i), acc)
    end)
  end

  def bind({:^, _, _}, _value, env), do: env

  def bind(other, _value, env) do
    # An unsupported pattern can still rebind an existing name.
    {_, env} =
      Macro.prewalk(other, env, fn
        {:^, _, _}, acc -> {nil, acc}
        {name, _, nil} = node, acc when is_atom(name) -> {node, Map.delete(acc, name)}
        node, acc -> {node, acc}
      end)

    env
  end

  def read(env, name) do
    case Map.fetch(env, name) do
      {:ok, {_, value}} -> value
      :error -> Value.unknown()
    end
  end

  # Sibling arguments read the same incoming bindings. Their writes become
  # visible after the call, including an assignment back to an old literal.
  def merge_writes(base, base, acc), do: acc

  def merge_writes(base, changed, acc) do
    Enum.reduce(Map.keys(base) ++ Map.keys(changed), acc, fn key, merged ->
      case {Map.fetch(base, key), Map.fetch(changed, key)} do
        {same, same} -> merged
        {_, {:ok, binding}} -> Map.put(merged, key, binding)
        {_, :error} -> Map.delete(merged, key)
      end
    end)
  end
end
