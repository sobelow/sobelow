defmodule Sobelow.Parse.RegexPatterns do
  @moduledoc false

  alias Sobelow.Parse

  # Recognize only direct Regex.escape calls, including imports/aliases/pipes
  # resolved by the shared matcher. No evaluation or name-based wrapper trust.
  def unescaped_vars(fun, pattern) do
    escaped =
      fun
      |> Parse.calls_with_args([{[:Regex], :escape, [1]}])
      |> Enum.map(fn {call, _, _} -> call end)
      |> MapSet.new()

    pattern
    |> Macro.prewalk(fn
      {operator, _, [left, right]} when operator in [:<>, :++] -> [left, right]
      {:|>, _, [_, call]} = node -> if MapSet.member?(escaped, call), do: "", else: node
      node -> if MapSet.member?(escaped, node), do: "", else: node
    end)
    |> Parse.binary_input_vars()
  end
end
