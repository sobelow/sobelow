defmodule Sobelow.Parse.Flow do
  @moduledoc false

  alias Sobelow.Parse.Flow.{Eval, LiveView}
  alias Sobelow.Parse.Metadata
  alias Sobelow.Utils

  def for_argument(meta, index), do: meta |> Map.get(:argument_flows, %{}) |> Map.get(index, %{})

  def definitions(ast, file, scopes) do
    scopes =
      if nested_modules?(ast),
        do: Sobelow.Lexical.function_scopes(ast, project_modules: true),
        else: scopes

    modules(ast, [], file, scopes)
  end

  defp nested_modules?({:__block__, _, forms}) when is_list(forms),
    do: Enum.any?(forms, &nested_modules?/1)

  defp nested_modules?({:defmodule, _, [_, [do: body]]}),
    do: Enum.any?(forms(body), &match?({:defmodule, _, _}, &1))

  defp nested_modules?(_), do: false

  defp forms({:__block__, _, forms}) when is_list(forms), do: forms
  defp forms(form), do: [form]

  defp modules({:__block__, _, forms}, parent, file, scopes) when is_list(forms),
    do: Enum.flat_map(forms, &modules(&1, parent, file, scopes))

  defp modules({:defmodule, _, [{:__aliases__, _, names}, [do: body]]}, parent, file, scopes)
       when is_list(names) do
    module =
      case names do
        [:"Elixir" | rest] -> rest
        parts -> parent ++ parts
      end

    if module != [] and Enum.all?(module, &is_atom/1),
      do: module_forms(body, module, file, scopes),
      else: []
  end

  defp modules(_, _, _, _), do: []

  defp module_forms(body, module, file, scopes) do
    forms = forms(body)

    kind =
      cond do
        Utils.controller?(forms) -> :controller
        LiveView.module?(forms) -> :live_view
        true -> :module
      end

    own = Enum.flat_map(forms, &definition(&1, module, file, kind, scopes))
    own ++ Enum.flat_map(forms, &modules(&1, module, file, scopes))
  end

  defp definition({visibility, _, [head | rest]} = node, module, file, kind, scopes)
       when visibility in [:def, :defp, :defmacro, :defmacrop, :defdelegate] do
    case unguard(head) do
      {name, _, params} when is_atom(name) and (is_list(params) or is_nil(params)) ->
        params = params || []

        body =
          case rest do
            [[do: body]] when visibility in [:def, :defp] -> {:ok, body}
            _ -> :opaque
          end

        [
          %{
            module: module,
            name: name,
            params: params,
            arity: length(params),
            file: file,
            kind: kind,
            visibility: visibility,
            body: body,
            return: return_summary(body, params),
            head: head,
            definition_key: Metadata.definition_key(node),
            guarded?: head != unguard(head),
            scope: Map.get(scopes, Metadata.definition_key(node), %{})
          }
        ]

      _ ->
        []
    end
  end

  defp definition(_, _, _, _, _), do: []
  defp unguard({:when, _, [head | _]}), do: head
  defp unguard(head), do: head

  # Identity functions, field getters and constants have an exact return
  # summary that every caller can reuse without walking the helper again.
  defp return_summary({:ok, expr}, params) do
    case projection(expr, []) do
      {:param, name, fields} ->
        if Enum.any?(params, &match?({^name, _, nil}, &1)),
          do: {:param, name, fields},
          else: :interpret

      summary ->
        summary
    end
  end

  defp return_summary(_, _), do: :interpret
  defp projection({name, _, nil}, fields) when is_atom(name), do: {:param, name, fields}

  defp projection({{:., _, [Access, :get]}, _, [obj, key]}, fields)
       when is_binary(key) or is_atom(key),
       do: projection(obj, [key | fields])

  defp projection({{:., _, [obj, key]}, meta, []}, fields) when is_atom(key) do
    if meta[:no_parens], do: projection(obj, [key | fields]), else: :interpret
  end

  defp projection(value, []) when is_atom(value) or is_binary(value) or is_number(value),
    do: {:literal, value}

  defp projection(_, _), do: :interpret

  def attach(files, templates) do
    defs = Enum.flat_map(files, & &1.flow_definitions)

    functions =
      for fun <- defs, arity <- arities(fun), reduce: %{} do
        acc -> Map.update(acc, {fun.module, fun.name, arity}, fun, fn _ -> :ambiguous end)
      end

    {flows, sockets} =
      defs
      |> Enum.sort_by(
        &{&1.file, Sobelow.Parse.get_fun_line(&1.head), Sobelow.Parse.get_fun_column(&1.head)}
      )
      |> Enum.reduce({%{}, %{}}, fn fun, acc -> Eval.entry(fun, functions, acc) end)

    {inline, templates} = LiveView.templates(defs, sockets, templates)

    files =
      Enum.map(files, fn meta ->
        contexts =
          Enum.map(
            meta.scan_contexts,
            &Map.put(&1, :argument_flows, Map.get(flows, meta.filename, %{}))
          )

        meta
        |> Map.delete(:flow_definitions)
        |> Map.put(:scan_contexts, contexts)
        |> Map.put(:live_renders, Map.get(inline, meta.filename, %{}))
      end)

    {files, templates}
  end

  defp arities(fun) do
    defaults = Enum.count(fun.params, &match?({:\\, _, _}, &1))
    (fun.arity - defaults)..fun.arity
  end
end
