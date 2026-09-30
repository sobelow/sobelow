defmodule Sobelow.Parse.Metadata do
  @moduledoc false

  alias Sobelow.Parse.Calls
  alias Sobelow.Parse.Source

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
    {ast, acc ++ associate_skips_with_pipelines(stmts)}
  end

  defp collect_skip_associations(ast, acc), do: {ast, acc}

  # Only adjacent attributes in the same block bind to a pipeline. A pipeline
  # with a skip always has a block containing both statements.
  defp associate_skips_with_pipelines(statements) do
    {associations, _pending} =
      Enum.reduce(statements, {[], []}, fn
        {:@, _, [{:sobelow_skip, _, [skips]}]} = attr, {acc, pending} when is_list(skips) ->
          {acc, pending ++ [{attr, skips}]}

        {:pipeline, _, _} = pipeline, {acc, pending} ->
          {[{pipeline, pending} | acc], []}

        _, {acc, _pending} ->
          {acc, []}
      end)

    Enum.map(associations, fn {pipeline, pending} ->
      {pipeline, Enum.flat_map(pending, &elem(&1, 1)), Enum.map(pending, &elem(&1, 0))}
    end)
  end

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
