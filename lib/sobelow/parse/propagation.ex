defmodule Sobelow.Parse.Propagation do
  @moduledoc false

  alias Sobelow.Lexical
  alias Sobelow.Parse.Metadata
  alias Sobelow.Parse.Propagation.Eval

  # A scan supplies only its eligible sources. Identity includes the full literal
  # module path and *call* arity; neither a BEAM lookup nor macro expansion occurs.
  def index(sources) do
    entries =
      Enum.flat_map(sources, fn {ast, file} ->
        scopes = Lexical.function_scopes(ast, project_modules: true)
        definitions(ast, [], file, scopes)
      end)

    declarations =
      entries
      |> Enum.filter(&(&1.body == :declaration))
      |> Enum.group_by(&{&1.module, &1.name, &1.arity})

    {functions, unresolved} =
      entries
      |> Enum.reject(&(&1.body == :declaration))
      |> Enum.reduce({%{}, MapSet.new()}, fn entry, {functions, unresolved} ->
        declarations = Map.get(declarations, {entry.module, entry.name, entry.arity}, [])
        declarations = if declarations == [], do: [entry], else: declarations

        Enum.reduce(declarations, {functions, unresolved}, fn declaration,
                                                              {functions, unresolved} ->
          defaults = Enum.filter(declaration.params, &match?({:\\, _, _}, &1))

          Enum.reduce(0..length(defaults), {functions, unresolved}, fn missing,
                                                                       {functions, unresolved} ->
            key = {entry.module, entry.name, entry.arity - missing}
            selected = Enum.take(defaults, missing)

            if Enum.all?(selected, fn {:\\, _, [_, value]} -> Macro.quoted_literal?(value) end) do
              call =
                {entry, Enum.map(selected, fn {:\\, _, [_, value]} -> value end), declaration}

              {Map.update(functions, key, [call], &[call | &1]), unresolved}
            else
              {functions, MapSet.put(unresolved, key)}
            end
          end)
        end)
      end)

    %{
      functions: Map.new(functions, fn {key, clauses} -> {key, Enum.uniq(clauses)} end),
      unresolved_defaults: unresolved
    }
  end

  def run(project, signature, arguments, opts \\ []) do
    Eval.run(project, signature, arguments, opts)
  end

  defp definitions({:__block__, _, nodes}, parent, file, scopes),
    do: Enum.flat_map(nodes, &definitions(&1, parent, file, scopes))

  defp definitions({kind, _, [{:__aliases__, _, names}, [do: body]]}, parent, file, scopes)
       when kind in [:defmodule, :defprotocol] and is_list(names) do
    module = if List.first(names) == :"Elixir", do: tl(names), else: parent ++ names

    if module != [] and Enum.all?(module, &is_atom/1) do
      body |> forms() |> Enum.flat_map(&definition(&1, module, file, scopes))
    else
      []
    end
  end

  # Implementations may select target types dynamically; their generated
  # module names are not statically defined by the protocol alias alone.
  defp definitions({:defimpl, _, _}, _, _, _), do: []

  defp definitions(_, _, _, _), do: []

  defp definition({visibility, _, [head | rest]} = node, module, file, scopes)
       when visibility in [:def, :defp] do
    case unguard(head) do
      {name, _, params} when is_atom(name) and (is_list(params) or is_nil(params)) ->
        body =
          case rest do
            [[do: value]] -> {:ok, value}
            _ -> :declaration
          end

        [
          %{
            module: module,
            name: name,
            arity: length(params || []),
            params: params || [],
            head: head,
            body: body,
            visibility: visibility,
            file: file,
            scope: Map.get(scopes, Metadata.definition_key(node), %{})
          }
        ]

      _ ->
        []
    end
  end

  defp definition(node, module, file, scopes), do: definitions(node, module, file, scopes)
  defp forms({:__block__, _, nodes}), do: nodes
  defp forms(node), do: [node]
  defp unguard({:when, _, [head | _]}), do: head
  defp unguard(head), do: head
end
