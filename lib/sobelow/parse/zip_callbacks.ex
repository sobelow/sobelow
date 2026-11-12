defmodule Sobelow.Parse.ZipCallbacks do
  @moduledoc false

  @scopes [:fn, :quote, :&, :case, :if, :unless, :cond, :with, :for, :receive, :try]

  # Only inline, unguarded four-argument clauses are associated with ZIP's
  # content accessor. Delegation, accessor aliases and nested scopes are unknown.
  def content_callback?({:fn, _, clauses}), do: Enum.any?(clauses, &content_clause?/1)
  def content_callback?(_), do: false

  defp content_clause?({:->, _, [[_, _, {name, _, context}, _], body]})
       when is_atom(name) and name != :_ and is_atom(context) do
    invoked?(body, name)
  end

  defp content_clause?(_), do: false

  defp rebound?({:=, _, [pattern, value]}, name),
    do: variable?(pattern, name) or rebound?(value, name)

  defp rebound?({scope, _, _}, _) when scope in @scopes, do: false
  defp rebound?(node, name), do: children_any?(node, &rebound?(&1, name))

  defp variable?({name, _, context}, name) when is_atom(context), do: true
  defp variable?(node, name), do: children_any?(node, &variable?(&1, name))

  # Rebinding takes effect after its RHS and after the current expression.
  # Preserve calls made before that point; sibling arguments see the old binding.
  defp invoked?({:__block__, _, statements}, name) do
    Enum.reduce_while(statements, false, fn statement, _ ->
      cond do
        invoked?(statement, name) -> {:halt, true}
        rebound?(statement, name) -> {:halt, false}
        true -> {:cont, false}
      end
    end)
  end

  defp invoked?({:=, _, [_pattern, value]}, name), do: invoked?(value, name)

  defp invoked?({{:., _, [{name, _, context}]}, _, []}, name) when is_atom(context),
    do: true

  defp invoked?({scope, _, _}, _) when scope in @scopes, do: false
  defp invoked?(node, name), do: children_any?(node, &invoked?(&1, name))

  defp children_any?(node, predicate) when is_tuple(node),
    do: node |> Tuple.to_list() |> Enum.any?(predicate)

  defp children_any?(node, predicate) when is_list(node), do: Enum.any?(node, predicate)
  defp children_any?(_, _), do: false
end
