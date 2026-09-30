defmodule Sobelow.Parse.Calls do
  @moduledoc false

  import Sobelow.Parse.Variables,
    only: [extract_opts: 2, get_fun_declaration: 1, get_pipe_val: 2, normalize_finding: 1]

  def get_fun_vars_and_meta(fun, idx, type, module) do
    {params, {fun_name, line_no}} = get_fun_declaration(fun)

    pipefuns = get_funs_from_pipe(fun, type, module)
    pipevars = get_pipefuns_vars(pipefuns, fun, idx)

    vars =
      (get_funs(fun, type, module) -- pipefuns)
      |> get_funs_vars(idx, type, module)

    {vars ++ pipevars, params, {fun_name, line_no}}
  end

  def get_erlang_fun_vars_and_meta(fun, idx, type, module) do
    {params, {fun_name, line_no}} = get_fun_declaration(fun)

    pipefuns = get_erlang_funs_from_pipe(fun, type, module)
    pipevars = get_pipefuns_vars(pipefuns, fun, idx)

    vars =
      (get_erlang_aliased_funs_of_type(fun, type, module) -- pipefuns)
      |> get_funs_vars(idx, type, module)

    {vars ++ pipevars, params, {fun_name, line_no}}
  end

  defp get_funs(fun, type, module) do
    if Sobelow.Lexical.active?() and module != nil do
      target =
        case module do
          {:required, target} -> target
          target -> target
        end

      get_aliased_funs_of_type(fun, type, target) ++
        Enum.filter(get_funs_of_type(fun, type), &Sobelow.Lexical.unqualified?(&1, target))
    else
      legacy_funs(fun, type, module)
    end
  end

  defp legacy_funs(fun, type, nil), do: get_funs_of_type(fun, type)

  defp legacy_funs(fun, type, module) when is_list(module),
    do: get_aliased_funs_of_type(fun, type, module)

  defp legacy_funs(fun, type, {:required, module}),
    do: get_aliased_funs_of_type(fun, type, module)

  defp legacy_funs(fun, type, module),
    do: get_aliased_funs_of_type(fun, type, module) ++ get_funs_of_type(fun, type)

  defp get_funs_from_pipe(fun, type, module) do
    fun
    |> get_pipe_funs()
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(fn node ->
      case module do
        nil ->
          get_piped_funs_of_type(node, type)

        {:required, target} ->
          qualified_pipe(node, type, target)

        target when is_list(target) ->
          qualified_pipe(node, type, target)

        target ->
          if Sobelow.Lexical.active?(),
            do: qualified_pipe(node, type, target),
            else: qualified_pipe(node, type, target) ++ unqualified_pipe(node, type, target)
      end
    end)
    |> Enum.uniq()
  end

  defp qualified_pipe(node, type, target) do
    get_piped_aliased_funs_of_type(node, type, target) ++
      if(Sobelow.Lexical.active?(), do: unqualified_pipe(node, type, target), else: [])
  end

  defp unqualified_pipe(node, type, target) do
    get_piped_funs_of_type(node, type)
    |> Enum.filter(fn node ->
      not Sobelow.Lexical.active?() or Sobelow.Lexical.unqualified?(node, target, 1)
    end)
  end

  def get_erlang_funs_from_pipe(fun, type, module) do
    get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&get_piped_erlang_aliased_funs_of_type(&1, type, module))
    |> Enum.uniq()
  end

  defp get_funs_vars(funs, idx, _type, _module) do
    funs
    |> Enum.map(&{&1, extract_opts(&1, idx)})
    |> Enum.map(&normalize_finding/1)
    |> Enum.reject(fn {_, vars} ->
      is_list(vars) && Enum.empty?(vars)
    end)
  end

  defp get_pipefuns_vars(pipefuns, fun, 0) do
    pipefuns
    |> Enum.map(&{&1, get_pipe_val(fun, &1)})
    |> Enum.map(&normalize_finding/1)
    |> Enum.reject(fn {_, vars} ->
      is_list(vars) && Enum.empty?(vars)
    end)
  end

  defp get_pipefuns_vars(pipefuns, _fun, idx) do
    idx = idx - 1

    pipefuns
    |> Enum.map(&{&1, extract_opts(&1, idx)})
    |> Enum.map(&normalize_finding/1)
    |> Enum.reject(fn {_, vars} ->
      is_list(vars) && Enum.empty?(vars)
    end)
  end

  def get_erlang_funs_of_type(ast, type) do
    indexed_funs(ast, :qualified, type, &get_erlang_funs_of_type(&1, &2, type, :erlang))
  end

  def get_erlang_funs_of_type({{:., _, [module, type]}, _, _} = ast, acc, type, module) do
    {ast, [ast | acc]}
  end

  def get_erlang_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type, module) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_erlang_funs_of_type(fun_cap, acc, type, module)
  end

  def get_erlang_funs_of_type(ast, acc, _type, _module), do: {ast, acc}

  def get_erlang_aliased_funs_of_type(ast, type, module) do
    indexed_funs(ast, :qualified, type, &get_erlang_funs_of_type(&1, &2, type, module))
  end

  def get_piped_erlang_aliased_funs_of_type(ast, type, module) do
    case ast do
      {{:., _, [^module, ^type]}, _, _} ->
        [ast]

      _ ->
        []
    end
  end

  def get_funs_by_module(ast, module) do
    {_, acc} = Macro.prewalk(ast, [], &contains_module(&1, &2, module))
    acc
  end

  def get_assigns_from(fun, module) when is_list(module) do
    get_funs_of_type(fun, :=)
    |> Enum.filter(&contains_module?(&1, module))
    |> Enum.map(&get_assign/1)
  end

  defp contains_module?(ast, module) do
    {_, acc} = Macro.prewalk(ast, [], &contains_module(&1, &2, module))
    acc != []
  end

  defp contains_module({{:., _, [{:__aliases__, _, module}, _]}, _, _} = ast, acc, module) do
    {module, [ast | acc]}
  end

  defp contains_module(ast, acc, _), do: {ast, acc}

  defp get_assign({_, _, [{val, _, _} | _]}), do: val
  defp get_assign(_), do: ""

  # Lists require a complete alias match; atom targets accept the last segment
  # outside lexical analysis. Resolved lexical aliases take precedence.
  def get_aliased_funs_of_type(ast, type, module) when is_list(module) do
    indexed_funs(ast, :qualified, type, &get_strict_aliased_funs_of_type(&1, &2, type, module))
  end

  def get_aliased_funs_of_type(ast, type, module) do
    indexed_funs(ast, :qualified, type, &get_aliased_funs_of_type(&1, &2, type, module))
  end

  def get_strict_aliased_funs_of_type(ast, acc, type, module),
    do: get_aliased_funs_of_type(ast, acc, type, module)

  def get_aliased_funs_of_type(
        {{:., _, [{:__aliases__, _, aliases}, type]}, _, _opts} = ast,
        acc,
        type,
        module
      ) do
    if alias_matches?(ast, aliases, module) do
      {ast, [ast | acc]}
    else
      {ast, acc}
    end
  end

  def get_aliased_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type, module) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_aliased_funs_of_type(fun_cap, acc, type, module)
  end

  def get_aliased_funs_of_type(ast, acc, _type, _module) do
    {ast, acc}
  end

  def alias_matches?(ast, aliases, target) do
    if Sobelow.Lexical.active?() do
      case Sobelow.Lexical.matches?(ast, target) do
        nil -> legacy_alias_match?(aliases, target)
        matched? -> matched?
      end
    else
      legacy_alias_match?(aliases, target)
    end
  end

  defp legacy_alias_match?(aliases, target) do
    if is_list(target), do: aliases == target, else: List.last(aliases) == target
  end

  def get_piped_aliased_funs_of_type(ast, type, module) do
    case ast do
      {{:., _, [{:__aliases__, _, aliases}, ^type]}, _, _} ->
        if alias_matches?(ast, aliases, module), do: [ast], else: []

      _ ->
        []
    end
  end

  def get_top_level_funs_of_type(ast, type) do
    {_, acc} = Macro.prewalk(ast, [], &get_top_level_funs_of_type(&1, &2, type))
    acc
  end

  def get_top_level_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_top_level_funs_of_type(fun_cap, acc, type)
  end

  def get_top_level_funs_of_type({type, _, _} = ast, acc, type) do
    {[], [ast | acc]}
  end

  def get_top_level_funs_of_type(ast, acc, _type) do
    {ast, acc}
  end

  def get_funs_of_type(ast, type) do
    indexed_funs(ast, :bare, type, &get_funs_of_type(&1, &2, type))
  end

  defp indexed_funs(ast, kind, type, matcher) do
    case Sobelow.FunctionAnalysis.candidates(ast, kind, type) do
      {:ok, nodes} ->
        Enum.filter(nodes, fn node -> elem(matcher.(node, []), 1) != [] end)

      :error ->
        {_, acc} = Macro.prewalk(ast, [], matcher)
        acc
    end
  end

  # Bare-call matching excludes declaration heads; qualified calls keep theirs.
  def get_funs_of_type({name, _, opts}, acc, type) when name in [:def, :defp, :defmacro] do
    case Macro.prewalk(opts, [], &get_do_block/2) do
      {_, [[{:do, block}]]} ->
        get_funs_of_type(block, acc, type)

      _ ->
        {[], acc}
    end
  end

  def get_funs_of_type({type, _, _} = ast, acc, types) when is_list(types) do
    if Enum.member?(types, type) do
      {ast, [ast | acc]}
    else
      {ast, acc}
    end
  end

  def get_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_funs_of_type(fun_cap, acc, type)
  end

  def get_funs_of_type({type, _, _} = ast, acc, type) do
    {ast, [ast | acc]}
  end

  def get_funs_of_type(ast, acc, _type), do: {ast, acc}

  def get_piped_funs_of_type(ast, type) do
    case ast do
      {^type, _, _} ->
        [ast]

      _ ->
        []
    end
  end

  @doc false
  def create_fun_cap(fun, meta, idx) when is_number(idx) and idx > 0 do
    opts = Enum.map(1..trunc(idx), fn i -> {:&, [], [i]} end)
    {fun, meta, opts}
  end

  def create_fun_cap(fun, meta, _) do
    {fun, meta, [{:&, [], []}]}
  end

  def get_pipe_funs(ast) do
    Sobelow.FunctionAnalysis.fetch(ast, :pipes, fn ->
      ast
      |> get_funs_of_type(:|>)
      |> Enum.filter(fn pipe ->
        {_, acc} = Macro.prewalk(pipe, [], &get_do_block/2)
        Enum.empty?(acc)
      end)
    end)
  end

  def get_do_block({:|>, _, [_, {_, _, [[do: _block]]}]} = ast, acc) do
    {[], [ast | acc]}
  end

  def get_do_block([do: _block] = ast, acc), do: {[], [ast | acc]}
  def get_do_block(ast, acc), do: {ast, acc}
end
