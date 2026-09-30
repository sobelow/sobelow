defmodule Sobelow.FunctionAnalysis do
  @moduledoc false
  @key {__MODULE__, :context}

  # A worker retains only the current function's analysis. Public parsing
  # helpers still walk normally when used outside this scope or on a subtree.
  def with_fun(ast, fun) do
    previous = Process.get(@key)
    Process.put(@key, {ast, %{}})

    try do
      fun.()
    after
      Process.put(@key, previous)
    end
  end

  def fetch(ast, key, fun) do
    case Process.get(@key) do
      {^ast, cache} ->
        case Map.fetch(cache, key) do
          {:ok, value} ->
            value

          :error ->
            value = fun.()
            {^ast, cache} = Process.get(@key)
            Process.put(@key, {ast, Map.put(cache, key, value)})
            value
        end

      _ ->
        fun.()
    end
  end

  def candidates(ast, kind, type) when is_atom(type) do
    case Process.get(@key) do
      {^ast, _} -> {:ok, Map.get(fetch(ast, kind, fn -> index(ast, kind) end), type, [])}
      _ -> :error
    end
  end

  def candidates(_ast, _kind, _type), do: :error

  def confidence_aliases(ast, node) do
    case Process.get(@key) do
      {^ast, _} ->
        {nodes, last_aliases} = fetch(ast, :confidence_aliases, fn -> alias_index(ast) end)
        {:ok, Map.get(nodes, node, last_aliases)}

      _ ->
        :error
    end
  end

  defp alias_index({_, _, [_head, [do: body]]}) do
    statements =
      case body do
        {:__block__, _, list} -> list
        single -> [single]
      end

    Enum.reduce(statements, {%{}, %{}}, fn statement, {nodes, aliases} ->
      {_, nodes} =
        Macro.prewalk(statement, nodes, fn
          {_, _, args} = node, nodes when is_list(args) ->
            {node, Map.put_new(nodes, node, aliases)}

          node, nodes ->
            {node, nodes}
        end)

      {nodes, track_alias(statement, aliases)}
    end)
  end

  defp track_alias({:=, _, [{left, _, nil}, {right, _, nil}]}, aliases)
       when is_atom(left) and is_atom(right),
       do: Map.put(aliases, left, Map.get(aliases, right, right))

  defp track_alias({:=, _, [{left, _, nil}, _]}, aliases) when is_atom(left),
    do: Map.delete(aliases, left)

  defp track_alias(_, aliases), do: aliases

  defp index(ast, kind) do
    {_, calls} = Macro.prewalk(ast, %{}, &collect(&1, &2, kind))
    calls
  end

  # The bare matcher excludes declaration heads/defaults and unwraps do blocks.
  # The qualified matcher historically visits the complete AST. Keep separate
  # indexes so neither traversal silently changes what a check sees.
  defp collect({name, _, opts}, calls, :bare) when name in [:def, :defp, :defmacro] do
    case Macro.prewalk(opts, [], &Sobelow.Parse.get_do_block/2) do
      {_, [[{:do, block}]]} -> collect(block, calls, :bare)
      _ -> {[], calls}
    end
  end

  defp collect({:&, _, [{:/, _, [{fun, meta, _}, arity]}]}, calls, kind) do
    collect(Sobelow.Parse.create_fun_cap(fun, meta, arity), calls, kind)
  end

  defp collect({name, _, _} = node, calls, :bare) when is_atom(name),
    do: {node, Map.update(calls, name, [node], &[node | &1])}

  defp collect({{:., _, [_module, name]}, _, _} = node, calls, :qualified) when is_atom(name),
    do: {node, Map.update(calls, name, [node], &[node | &1])}

  defp collect(node, calls, _kind), do: {node, calls}
end
