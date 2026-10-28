defmodule Sobelow.Parse.FileSelection do
  @moduledoc false

  alias Sobelow.Parse

  @string_sigils [:sigil_c, :sigil_C, :sigil_s, :sigil_S]

  # Specifications are {function, arities, filename_index, directories_index}.
  def findings(fun, specifications) do
    indexes = Map.new(specifications, fn {name, _, f, d} -> {name, {f, d}} end)
    calls = Enum.map(specifications, fn {name, arities, _, _} -> {:file, name, arities} end)

    for {call, name, args} <- Parse.calls_with_args(fun, calls),
        variables = variables(args, Map.fetch!(indexes, name)),
        variables != [],
        do: {call, variables}
  end

  defp variables(args, {filename_index, directories_index}) do
    filename = args |> Enum.at(filename_index) |> normalize_path_strings()

    directories =
      if directories_index != nil and not absolute_literal?(filename),
        do: args |> Enum.at(directories_index) |> normalize_path_strings() |> variables(),
        else: []

    Enum.uniq(variables(filename) ++ directories)
  end

  # Expects a value already passed through normalize_path_strings/1.
  defp variables(normalized) do
    if Macro.quoted_literal?(normalized) do
      []
    else
      case Parse.extract_opts({:argument, [], [normalized]}, 0)
           |> List.wrap()
           |> List.flatten() do
        [] -> ["dynamic file selection"]
        variables -> variables
      end
    end
  end

  defp normalize_path_strings(ast) do
    Macro.prewalk(ast, fn
      {sigil, _, [{:<<>>, _, parts} = contents, []]} when sigil in @string_sigils ->
        case parts do
          [value] when is_binary(value) -> value
          _ -> contents
        end

      # Legacy single-quoted charlist interpolation.
      {{:., _, [List, :to_charlist]}, meta, [contents]} when is_list(contents) ->
        {:<<>>, meta, contents}

      node ->
        node
    end)
  end

  # The filename API follows the scanning host's path semantics.
  defp absolute_literal?(value) when is_binary(value) or is_list(value),
    do: Path.type(value) == :absolute

  defp absolute_literal?(value) when is_atom(value),
    do: value |> Atom.to_string() |> Path.type() == :absolute

  defp absolute_literal?(_), do: false
end
