defmodule Sobelow.Lexical do
  @moduledoc false
  @context_key {__MODULE__, :context}
  @local_sinks %{raw: :HTML, put_resp_header: :Conn, put_resp_content_type: :Conn}
  @modules %{
    SQL: [:Ecto, :Adapters, :SQL],
    HTML: [:Phoenix, :HTML],
    Conn: [:Plug, :Conn],
    Controller: [:Phoenix, :Controller]
  }

  def functions(ast) do
    {_env, acc} =
      walk(ast, %{aliases: %{}, imports: %{}, repo?: false, local_functions: []}, %{
        functions: %{},
        calls: %{}
      })

    acc.functions
  end

  def with_context(context, fun) do
    previous = Process.get(@context_key)
    Process.put(@context_key, context)

    try do
      fun.()
    after
      Process.put(@context_key, previous)
    end
  end

  def active?, do: is_map(Process.get(@context_key))

  def index_inline(ast, sigil) do
    case resolution(sigil) do
      %{aliases: _} = env ->
        {_env, acc} = walk(ast, env, %{functions: %{}, calls: %{}})
        Process.put(@context_key, Map.merge(Process.get(@context_key), acc.calls))

      _ ->
        :ok
    end

    ast
  end

  def matches?(node, target) do
    case resolution(node) do
      %{module: module} when is_list(module) ->
        cond do
          is_list(target) -> module == target
          target == :Repo -> List.last(module) == :Repo
          Map.has_key?(@modules, target) -> module == Map.fetch!(@modules, target)
          true -> List.last(module) == target
        end

      _ ->
        nil
    end
  end

  def unqualified?({name, _, args} = node, target, extra \\ 0) do
    case resolution(node) do
      %{imports: imports, repo?: repo?} = env ->
        module = if is_list(target), do: target, else: Map.get(@modules, target, [target])
        arity = length(args || []) + extra

        if Map.get(@local_sinks, name) == target and shadowed?(env, module, {name, arity}) do
          false
        else
          (is_atom(target) and target not in [:SQL, :Repo]) or
            (target == :Repo and repo? and name in [:query, :query!]) or
            imported?(Map.get(imports, module), {name, arity})
        end

      _ ->
        is_atom(target) and target not in [:SQL, :Repo]
    end
  end

  defp shadowed?(env, module, signature) do
    signature in Map.get(env, :local_functions, []) or
      excluded_import?(env.imports, module, signature) or
      conflicting_import?(env.imports, module, signature)
  end

  defp excluded_import?(imports, module, signature) do
    case Map.fetch(imports, module) do
      {:ok, {:unknown, _}} -> module == [:Plug, :Conn]
      {:ok, selection} -> not imported?(selection, signature)
      :error -> false
    end
  end

  defp conflicting_import?(imports, module, signature) do
    known_target? = imported?(Map.get(imports, module), signature)

    Enum.any?(imports, fn
      {^module, _selection} ->
        false

      {_other, {:only, functions}} ->
        signature in functions

      {_other, selection} ->
        module == [:Plug, :Conn] and not known_target? and possible_import?(selection, signature)
    end)
  end

  defp possible_import?({:macros, _}, _signature), do: true
  defp possible_import?(selection, signature), do: imported?(selection, signature)

  defp resolution(node) do
    context = Process.get(@context_key) || %{}
    Map.get(context, node_key(node)) || Map.get(context, node)
  end

  # AST keys with large nested pipes lose heap sharing when sent to workers.
  # Encoded keys keep exact node identity while binaries share across processes.
  # Older OTP releases without deterministic encoding retain the AST keys.
  defp node_key(node) do
    capability = {__MODULE__, :binary_keys}

    supported? =
      case Process.get(capability) do
        nil ->
          supported? = deterministic_encoding?()
          Process.put(capability, supported?)
          supported?

        supported? ->
          supported?
      end

    if supported?, do: :erlang.term_to_binary(node, [:deterministic]), else: node
  end

  defp deterministic_encoding? do
    :erlang.term_to_binary(nil, [:deterministic])
    true
  rescue
    ArgumentError -> false
  end

  defp imported?({:only, functions}, signature) when is_list(functions),
    do: signature in functions

  defp imported?({:except, functions}, signature) when is_list(functions),
    do: signature not in functions

  defp imported?({:unknown, excluded}, signature), do: signature not in excluded

  defp imported?(_, _), do: false

  def uncertain?({name, _, _} = node) when name in [:query, :query!, :stream] do
    case resolution(node) do
      %{imports: imports} ->
        case Map.get(imports, [:Ecto, :Adapters, :SQL]) do
          {:unknown, _} -> true
          _ -> false
        end

      _ ->
        false
    end
  end

  def uncertain?(_node), do: false

  defp import_selection(options, previous) do
    if Keyword.keyword?(options) do
      cond do
        Keyword.get(options, :only) == :functions ->
          {:except, []}

        Keyword.get(options, :only) == :macros ->
          {:macros, []}

        Keyword.has_key?(options, :only) ->
          selection(:only, Keyword.get(options, :only))

        Keyword.has_key?(options, :except) ->
          case selection(:except, Keyword.get(options, :except)) do
            {:except, excluded} -> exclude(previous, excluded)
            unknown -> unknown
          end

        true ->
          {:except, []}
      end
    else
      {:unknown, []}
    end
  end

  defp selection(kind, signatures) when is_list(signatures) do
    if Enum.all?(signatures, fn
         {name, arity} -> is_atom(name) and is_integer(arity) and arity >= 0
         _ -> false
       end), do: {kind, signatures}, else: {:unknown, []}
  end

  defp selection(_kind, _signatures), do: {:unknown, []}

  defp walk({:__block__, _, nodes}, env, acc), do: walk(nodes, env, acc)

  defp walk({:defmodule, _, [_name, [do: body]]}, env, acc) do
    # Local definitions apply throughout their module, including before their
    # declaration. Nested modules inherit imports and aliases, not local functions.
    {_inner, acc} = walk(body, Map.put(env, :local_functions, local_functions(body)), acc)
    {env, acc}
  end

  defp walk({kind, _, [_head, [do: body]]} = node, env, acc) when kind in [:def, :defp] do
    {_inner, local} = walk(body, env, %{functions: %{}, calls: %{}})
    {env, %{acc | functions: Map.put(acc.functions, node, local.calls)}}
  end

  defp walk({:alias, _, [module | options]}, env, acc) do
    aliases = alias_entries(module, env)
    options = List.flatten(options)
    as = if Keyword.keyword?(options), do: Keyword.get(options, :as)

    aliases =
      Enum.reduce(aliases, env.aliases, fn segments, aliases ->
        name =
          if as,
            do: List.last(module_name(as, %{env | aliases: %{}}) || segments),
            else: List.last(segments)

        Map.put(aliases, name, segments)
      end)

    {%{env | aliases: aliases}, acc}
  end

  defp walk({:import, _, [module | options]}, env, acc) do
    module = module_name(module, env)
    options = List.flatten(options)
    previous = Map.get(env.imports, module, {:except, []})

    selection = import_selection(options, previous)

    {%{env | imports: Map.put(env.imports, module, selection)}, acc}
  end

  defp walk({:use, _, [module | _]}, env, acc) do
    {%{env | repo?: env.repo? or module_name(module, env) == [:Ecto, :Repo]}, acc}
  end

  defp walk({:&, _, [{:/, _, [{fun, meta, _}, arity]}]}, env, acc) do
    # Parsing helpers represent named captures as synthetic calls. Index the
    # same call so alias resolution and import arities survive that conversion.
    walk(Sobelow.Parse.create_fun_cap(fun, meta, arity), env, acc)
  end

  defp walk({:sigil_H, _, _} = node, env, acc) do
    # The string's AST is parsed later, after source locations and assigns have
    # been normalized. Retain this sigil's scope for indexing those new nodes.
    {env, put_call(acc, node, env)}
  end

  defp walk({{:., _, [module, _]}, _, args} = node, env, acc) do
    acc = put_call(acc, node, %{module: module_name(module, env)})
    {_inner, acc} = walk(args, env, acc)
    {env, acc}
  end

  defp walk({name, _, args} = node, env, acc) when is_atom(name) and is_list(args) do
    acc =
      put_call(acc, node, %{
        imports: env.imports,
        repo?: env.repo?,
        local_functions: Map.get(env, :local_functions, [])
      })

    {_inner, acc} = walk(args, env, acc)
    {env, acc}
  end

  defp walk(nodes, env, acc) when is_list(nodes) do
    Enum.reduce(nodes, {env, acc}, fn node, {env, acc} -> walk(node, env, acc) end)
  end

  defp walk({_key, value}, env, acc) do
    {_inner, acc} = walk(value, env, acc)
    {env, acc}
  end

  defp walk(_, env, acc), do: {env, acc}

  defp local_functions({:__block__, _, nodes}) do
    signatures = Enum.flat_map(nodes, &local_functions/1) |> Enum.uniq()

    # A default declaration or a benign clause cannot hide an unsafe clause.
    if Enum.any?(nodes, &unsafe_raw_definition?/1),
      do: without_raw(signatures),
      else: signatures
  end

  defp local_functions({kind, _, [head | _]} = definition) when kind in [:def, :defp] do
    signatures = local_signatures(head)
    if unsafe_raw_definition?(definition), do: without_raw(signatures), else: signatures
  end

  defp local_functions({kind, _, [head | _]})
       when kind in [:defmacro, :defmacrop, :defdelegate] do
    # A macro or delegate may return the connection unchanged. It cannot prove
    # a content type, but an unresolved raw macro/delegate remains a possible sink.
    without_raw(local_signatures(head))
  end

  defp local_functions(_), do: []

  defp without_raw(signatures),
    do: Enum.reject(signatures, fn {name, _arity} -> name == :raw end)

  defp unsafe_raw_definition?({kind, _, [head, [do: body]]}) when kind in [:def, :defp] do
    Enum.any?(local_signatures(head), fn {name, _arity} -> name == :raw end) and
      unsafe_raw_body?(body)
  end

  defp unsafe_raw_definition?(_), do: false

  defp unsafe_raw_body?(body) do
    {_, unsafe?} =
      Macro.prewalk(body, false, fn
        {:safe, value} = node, unsafe? -> {node, unsafe? or not Macro.quoted_literal?(value)}
        {:raw, _, args} = node, _unsafe? when is_list(args) -> {node, true}
        {{:., _, [_, :raw]}, _, _} = node, _unsafe? -> {node, true}
        node, unsafe? -> {node, unsafe?}
      end)

    unsafe?
  end

  defp local_signatures({:when, _, [head | _]}), do: local_signatures(head)

  defp local_signatures({name, _, args})
       when is_map_key(@local_sinks, name) and is_list(args) do
    arity = length(args)
    defaults = Enum.count(args, &match?({:\\, _, _}, &1))
    Enum.map((arity - defaults)..arity, &{name, &1})
  end

  defp local_signatures(_), do: []

  defp put_call(acc, node, resolution),
    do: %{acc | calls: Map.put(acc.calls, node_key(node), resolution)}

  defp module_name({:__aliases__, _, [:"Elixir" | segments]}, _env), do: segments

  defp module_name({:__aliases__, _, [first | rest]}, env),
    do: Map.get(env.aliases, first, [first]) ++ rest

  defp module_name(_, _env), do: nil

  defp alias_entries({{:., _, [prefix, :{}]}, _, entries}, env) do
    case module_name(prefix, env) do
      prefix when is_list(prefix) ->
        Enum.flat_map(entries, fn entry ->
          case module_name(entry, %{env | aliases: %{}}) do
            suffix when is_list(suffix) -> [prefix ++ suffix]
            _ -> []
          end
        end)

      _ ->
        []
    end
  end

  defp alias_entries(module, env), do: List.wrap(module_name(module, env)) |> wrap_alias()
  defp wrap_alias([]), do: []
  defp wrap_alias(segments), do: [segments]

  defp exclude({:only, selected}, excluded) when is_list(excluded),
    do: {:only, selected -- excluded}

  defp exclude({:except, previous}, excluded) when is_list(excluded),
    do: {:except, previous ++ excluded}

  defp exclude({:unknown, previous}, excluded) when is_list(excluded),
    do: {:unknown, previous ++ excluded}

  defp exclude(_, _), do: {:unknown, []}
end
