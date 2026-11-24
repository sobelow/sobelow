defmodule Sobelow.Parse.Metadata do
  @moduledoc false

  alias Sobelow.Parse.Calls
  alias Sobelow.Parse.Source

  @function_kinds [:def, :defp]

  def get_meta_funs(filepath) when is_binary(filepath) do
    ast = Source.ast(filepath)
    get_meta_funs(ast)
  end

  def get_meta_funs(ast) do
    init_acc = %{def_funs: [], use_funs: [], import_funs: [], module_attrs: []}
    {_, acc} = Macro.prewalk(ast, init_acc, &get_meta_funs(&1, &2))

    # Pipeline skips must not also attach to the next function. Most files have
    # none, so avoid a second traversal unless a skip attribute was collected.
    if Enum.any?(acc.def_funs, &skip_attr?/1) do
      consumed = pipeline_skip_attrs(ast)
      Map.update!(acc, :def_funs, &Enum.reject(&1, fn fun -> MapSet.member?(consumed, fun) end))
    else
      acc
    end
  end

  @doc false
  # `use` and `import` belong to a module, not a whole source file. Keep
  # definitions beside the declarations that can affect their meaning.
  def get_module_meta_funs(ast) do
    {_, modules} =
      Macro.prewalk(ast, [], fn
        {:defmodule, _, [_, [do: body]]} = node, acc -> {node, [body | acc]}
        node, acc -> {node, acc}
      end)

    case modules do
      [] ->
        [get_meta_funs(ast)]

      bodies ->
        bodies
        |> Enum.reverse()
        |> Enum.map(fn body ->
          body
          |> Macro.prewalk(fn
            {:defmodule, _, _} -> {}
            node -> node
          end)
          |> get_meta_funs()
        end)
    end
  end

  @doc false
  def file_metadata(ast) do
    empty = %{def_funs: [], use_funs: [], import_funs: [], module_attrs: []}

    initial = %{
      file: empty,
      modules: %{},
      current: nil,
      parents: [],
      count: 0,
      captured_depth: 0,
      fallback?: false
    }

    {_, metadata} = Macro.traverse(ast, initial, &metadata_pre/2, &metadata_post/2)

    consumed =
      if Enum.any?(metadata.file.def_funs, &skip_attr?/1),
        do: pipeline_skip_attrs(ast),
        else: MapSet.new()

    clean = fn meta ->
      Map.update!(meta, :def_funs, &Enum.reject(&1, fn fun -> MapSet.member?(consumed, fun) end))
    end

    file = clean.(metadata.file)

    contexts =
      cond do
        metadata.fallback? -> get_module_meta_funs(ast)
        metadata.count == 0 -> [file]
        true -> Enum.map(0..(metadata.count - 1), &clean.(Map.fetch!(metadata.modules, &1)))
      end

    {file, contexts}
  end

  defp metadata_pre(node, metadata) do
    {_, file} = get_meta_funs(node, metadata.file)
    metadata = %{metadata | file: file}

    metadata =
      if captured_metadata?(node),
        do: %{metadata | captured_depth: metadata.captured_depth + 1},
        else: metadata

    case node do
      {:defmodule, _, [name, [do: _body]]} ->
        empty = %{def_funs: [], use_funs: [], import_funs: [], module_attrs: []}
        %{count: id, current: parent} = metadata

        metadata = %{
          metadata
          | modules: Map.put(metadata.modules, id, empty),
            current: id,
            count: id + 1,
            parents: [parent | metadata.parents],
            fallback?:
              metadata.fallback? or metadata.captured_depth > 0 or
                not literal_module_name?(name)
        }

        {node, metadata}

      {:defmodule, _, _} ->
        {node, %{metadata | fallback?: true}}

      _ ->
        modules =
          if metadata.current != nil do
            Map.update!(metadata.modules, metadata.current, fn meta ->
              elem(get_meta_funs(node, meta), 1)
            end)
          else
            metadata.modules
          end

        {node, %{metadata | modules: modules}}
    end
  end

  defp metadata_post({:defmodule, _, [_, [do: _]]} = node, metadata) do
    [parent | rest] = metadata.parents
    {node, %{metadata | current: parent, parents: rest}}
  end

  defp metadata_post(node, metadata) do
    metadata =
      if captured_metadata?(node),
        do: %{metadata | captured_depth: metadata.captured_depth - 1},
        else: metadata

    {node, metadata}
  end

  # The old extraction strips nested modules out of captured definitions and
  # attributes. Those unusual containers need its rewritten AST, rather than
  # the original node retained by the combined traversal.
  defp captured_metadata?({name, _, _}) when name in [:def, :defp, :defmacro, :use, :import, :@],
    do: true

  defp captured_metadata?(_node), do: false

  defp literal_module_name?({:__aliases__, _, parts}), do: Enum.all?(parts, &is_atom/1)
  defp literal_module_name?(name), do: is_atom(name)

  # A definition's identity survives the metadata fallback that removes nested
  # modules from its body. Source ASTs include both line and column metadata.
  def definition_key({kind, meta, [_head | _]}) when kind in @function_kinds,
    do: {kind, meta}

  def definition_key(_), do: nil

  def function_skips(ast) do
    if Sobelow.get_env(:skip) do
      {_, skips} =
        Macro.prewalk(ast, %{}, fn
          {:__block__, _, statements} = node, skips ->
            {node,
             Enum.reduce(associate_skips(statements, @function_kinds), skips, fn
               {definition, checks, _attrs}, acc ->
                 Map.put(acc, definition_key(definition), checks)
             end)}

          node, skips ->
            {node, skips}
        end)

      skips
    else
      %{}
    end
  end

  defp skip_attr?({:@, _, [{:sobelow_skip, _, _}]}), do: true
  defp skip_attr?(_), do: false

  @doc false
  # Pair pipelines with immediately preceding skip attributes. Collect all
  # pipelines independently so nested ones still run without associated skips.
  def get_pipelines_with_skips(ast) do
    skips = Map.new(skip_associations(ast), fn {pipeline, skips, _attrs} -> {pipeline, skips} end)

    ast
    |> Calls.get_funs_of_type(:pipeline)
    |> Enum.reverse()
    |> Enum.map(&{&1, Map.get(skips, &1, [])})
  end

  defp pipeline_skip_attrs(ast) do
    ast
    |> skip_associations()
    |> Enum.flat_map(fn {_pipeline, _skips, attrs} -> attrs end)
    |> MapSet.new()
  end

  # `Source.ast/1` only rewrites skip comments into attributes under `--skip`, so
  # without it there is nothing to associate and the walk can be skipped entirely.
  defp skip_associations(ast) do
    if Sobelow.get_env(:skip) do
      {_, acc} = Macro.prewalk(ast, [], &collect_skip_associations/2)
      acc
    else
      []
    end
  end

  defp collect_skip_associations({:__block__, _, stmts} = ast, acc) when is_list(stmts) do
    {ast, acc ++ associate_skips(stmts, [:pipeline])}
  end

  defp collect_skip_associations(ast, acc), do: {ast, acc}

  # A pending skip stays within its block. Function annotations may intervene
  # before a definition, while pipeline skips require an adjacent directive.
  defp associate_skips(statements, targets) do
    {associations, _pending} =
      Enum.reduce(statements, {[], []}, fn
        {:@, _, [{:sobelow_skip, _, [skips]}]} = attr, {acc, pending} when is_list(skips) ->
          if Enum.all?(skips, &is_binary/1), do: {acc, [{attr, skips} | pending]}, else: {acc, []}

        {:@, _, [{name, _, [_]}]}, state
        when targets == @function_kinds and name in [:doc, :impl, :deprecated] ->
          state

        {:@, _, [{:spec, _, [spec]}]}, {acc, [_ | _] = pending} when targets == @function_kinds ->
          {acc, [{:spec, spec} | pending]}

        {kind, _, [_ | _]} = statement, {acc, pending} when pending != [] ->
          if kind in targets,
            do: {[{statement, preceding_skips(pending, statement)} | acc], []},
            else: {acc, []}

        _, {acc, _pending} ->
          {acc, []}
      end)

    for {target, [_ | _] = skips} <- associations do
      {target, Enum.flat_map(skips, &elem(&1, 1)), Enum.map(skips, &elem(&1, 0))}
    end
  end

  # Walk back from the definition so a spec for another function cuts off
  # earlier skips while preserving any directive written below that spec.
  defp preceding_skips(pending, {_, _, [head | _]}) do
    Enum.reduce_while(pending, [], fn
      {:spec, spec}, acc ->
        if matching_spec?(spec, head), do: {:cont, acc}, else: {:halt, acc}

      skip, acc ->
        {:cont, [skip | acc]}
    end)
  end

  defp matching_spec?({:when, _, [spec | _]}, head), do: matching_spec?(spec, head)
  defp matching_spec?(spec, {:when, _, [head | _]}), do: matching_spec?(spec, head)

  defp matching_spec?({:"::", _, [{name, _, spec_args}, _]}, {name, _, args})
       when is_atom(name) and (is_list(spec_args) or is_nil(spec_args)) and
              (is_list(args) or is_nil(args)) do
    args = List.wrap(args)
    arity = length(args)
    defaults = Enum.count(args, &match?({:\\, _, _}, &1))
    length(List.wrap(spec_args)) in (arity - defaults)..arity
  end

  defp matching_spec?(_, _), do: false

  def get_meta_funs({:@, _, [{:sobelow_skip, _, _}]} = ast, acc) do
    if Sobelow.get_env(:skip) do
      {ast, Map.update!(acc, :def_funs, &[ast | &1])}
    else
      {ast, acc}
    end
  end

  def get_meta_funs({:def, _, nil} = ast, acc), do: {ast, acc}
  def get_meta_funs({:defp, _, nil} = ast, acc), do: {ast, acc}
  def get_meta_funs({:@, _, [{_, _, nil}]} = ast, acc), do: {ast, acc}

  def get_meta_funs({:def, _, _} = ast, acc) do
    {ast, Map.update!(acc, :def_funs, &[ast | &1])}
  end

  def get_meta_funs({:defp, _, _} = ast, acc) do
    {ast, Map.update!(acc, :def_funs, &[ast | &1])}
  end

  def get_meta_funs({:use, _, _} = ast, acc) do
    {ast, Map.update!(acc, :use_funs, &[ast | &1])}
  end

  def get_meta_funs({:import, _, _} = ast, acc) do
    {ast, Map.update!(acc, :import_funs, &[ast | &1])}
  end

  def get_meta_funs({:@, _, [attr | _]} = ast, acc) do
    {ast, Map.update!(acc, :module_attrs, &[attr | &1])}
  end

  def get_meta_funs(ast, acc), do: {ast, acc}
end
