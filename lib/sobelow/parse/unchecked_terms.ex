defmodule Sobelow.Parse.UncheckedTerms do
  @moduledoc false

  alias Sobelow.Parse
  alias Sobelow.Parse.Metadata

  @decoder [{[:Plug, :Crypto], :non_executable_binary_to_term, [2]}]
  @body_read [{[:Plug, :Conn], :read_body, [1, 2]}]
  @base64 [
    {[:Base], :decode64!, [1, 2]},
    {[:Base], :decode64, [1, 2]},
    {[:Base], :url_decode64!, [1, 2]},
    {[:Base], :url_decode64, [1, 2]}
  ]
  @scalar_guards [:is_integer, :is_binary, :is_atom, :is_float, :is_boolean]

  @request {__MODULE__, :request}
  @conn {__MODULE__, :conn}
  @none {__MODULE__, :none}
  @max_depth 5
  @max_clauses 12
  @max_evaluations 256
  @max_branches 256
  @budget_key {__MODULE__, :project_budget}
  @branch_budget_key {__MODULE__, :project_branch_budget}
  @truncated_key {__MODULE__, :project_truncated}

  # Index literal module/function identities without evaluating the inspected
  # project. Only definitions from files selected for this scan are eligible.
  def definitions(ast, filename, contexts, skips) do
    scopes = Sobelow.Lexical.function_scopes(ast, project_modules: true)

    controllers =
      for context <- contexts, fun <- context.def_funs, into: %{} do
        {Metadata.definition_key(fun), Sobelow.Utils.controller?(context.use_funs)}
      end

    module_definitions(ast, [], filename, scopes, controllers, skips)
  end

  def project(files) do
    entries = Enum.flat_map(files, & &1.term_definitions)

    defaults =
      entries
      |> Enum.reject(&body?/1)
      |> Enum.group_by(&{&1.module, &1.name, &1.arity}, &{default_arguments(&1), &1.scope})

    functions =
      entries
      |> Enum.filter(&body?/1)
      |> Enum.flat_map(fn entry ->
        declarations = Map.get(defaults, {entry.module, entry.name, entry.arity}, [])

        declarations =
          if declarations == [], do: [{default_arguments(entry), entry.scope}], else: declarations

        for {declaration, scope} <- declarations,
            missing <- 0..length(declaration),
            trailing = Enum.take(declaration, -missing),
            Enum.all?(trailing, &literal_default?/1) do
          {{entry.module, entry.name, entry.arity - missing},
           {entry, Enum.map(trailing, &default_value(&1, scope))}}
        end
      end)
      |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
      |> Map.new(fn {signature, clauses} -> {signature, Enum.uniq(clauses)} end)

    unresolved_defaults =
      entries
      |> Enum.filter(&body?/1)
      |> Enum.flat_map(fn entry ->
        declarations = Map.get(defaults, {entry.module, entry.name, entry.arity}, [])

        declarations =
          if declarations == [], do: [{default_arguments(entry), entry.scope}], else: declarations

        Enum.flat_map(declarations, fn {declaration, _scope} ->
          if declaration == [] do
            []
          else
            for missing <- 1..length(declaration),
                not Enum.all?(Enum.take(declaration, -missing), &literal_default?/1),
                do: {entry.module, entry.name, entry.arity - missing}
          end
        end)
      end)
      |> MapSet.new()

    %{
      functions: functions,
      entries: Enum.filter(entries, &body?/1),
      unresolved_defaults: unresolved_defaults
    }
  end

  defp body?(entry) do
    case List.last(elem(entry.fun, 2)) do
      options when is_list(options) -> Keyword.has_key?(options, :do)
      _ -> false
    end
  end

  defp literal_default?({:\\, _, [_param, literal]}), do: Macro.quoted_literal?(literal)

  # The project pass starts only at request-bearing public entry points. Its
  # facts are carried through a bounded set of literal project calls, never
  # inferred from trace rendering or from arbitrary dynamic dispatch.
  defp project_handoffs_for(entry, project) do
    case head_params(hd(elem(entry.fun, 2))) do
      params when is_list(params) ->
        env = Enum.reduce(params, %{}, &seed_param(&1, &2, entry.controller?))
        env = seed_resolver_args(env, :def, params)

        if Enum.any?(env, fn {_key, value} -> value in [@conn, @request] end) do
          values = Enum.map(params, &seeded_value(&1, env))
          Process.put(@budget_key, @max_evaluations)
          Process.put(@branch_budget_key, @max_branches)
          Process.put(@truncated_key, MapSet.new())

          try do
            {_result, uses} = evaluate(entry, values, project, [], 0, true)
            report_truncation(entry)
            uses
          after
            Process.delete(@budget_key)
            Process.delete(@branch_budget_key)
            Process.delete(@truncated_key)
          end
        else
          []
        end

      _ ->
        []
    end
  end

  def project_handoffs(%{entries: entries} = project) do
    entries
    |> Enum.filter(&(&1.visibility == :def and not ignored?(&1.skips)))
    |> Enum.flat_map(&project_handoffs_for(&1, project))
    |> Enum.uniq_by(fn {node, origin, _, _} -> {origin.filename, node} end)
  end

  defp ignored?(skips), do: Enum.any?(skips, &(&1 in ["Misc", "Misc.BinToTerm"]))

  defp seeded_value({:=, _, [_, {name, _, _}]}, env), do: Map.get(env, name)
  defp seeded_value({name, _, context}, env) when is_atom(context), do: Map.get(env, name)
  defp seeded_value(_, _), do: nil

  defp evaluate(entry, values, project, stack, depth, returning?) do
    signature = {entry.module, entry.name, entry.arity}

    cond do
      signature in stack ->
        incomplete(:recursive_call, values)

      depth >= @max_depth ->
        incomplete(:depth_limit, values)

      Process.get(@budget_key, 0) <= 0 ->
        incomplete(:evaluation_limit, values)

      true ->
        evaluate_body(entry, values, project, stack, depth, returning?)
    end
  end

  defp evaluate_body(entry, values, project, stack, depth, returning?) do
    signature = {entry.module, entry.name, entry.arity}
    Process.put(@budget_key, Process.get(@budget_key) - 1)
    fun = entry.fun
    options = List.last(elem(fun, 2))
    body = if is_list(options), do: Keyword.get(options, :do), else: nil

    locals = %{
      project: project,
      stack: [signature | stack],
      depth: depth + 1,
      wrappers: %{},
      scalars: MapSet.new()
    }

    Sobelow.Lexical.with_context(entry.scope, fn ->
      params = head_params(hd(elem(fun, 2)))

      env =
        Enum.zip(params, values)
        |> Enum.reduce(%{}, fn {param, value}, acc -> bind(param, value, acc) end)

      env = checked_guard(hd(elem(fun, 2)), env)

      {_env, uses, result} = walk(body, env, matches(fun), locals, entry, returning?)
      {result, uses}
    end)
  end

  defp incomplete(reason, values) do
    if tracked_values?(values), do: mark_truncated(reason)
    {nil, []}
  end

  defp tracked_values?(values), do: Enum.any?(values, &tracked_value?/1)

  defp tracked_value?(@request), do: true
  defp tracked_value?(@conn), do: true
  defp tracked_value?({:conn_field, _}), do: true
  defp tracked_value?({:decoded, _, _, _}), do: true
  defp tracked_value?({:field, value}), do: tracked_value?(value)
  defp tracked_value?({:base64, source}), do: tracked_value?(source)
  defp tracked_value?({:parts, values}), do: Enum.any?(values, &tracked_value?/1)
  defp tracked_value?({:alternatives, values}), do: Enum.any?(values, &tracked_value?/1)

  defp tracked_value?({:map, fields}),
    do: Enum.any?(fields, fn {_, value} -> tracked_value?(value) end)

  defp tracked_value?({:map_update, original, fields}),
    do: tracked_value?(original) or tracked_value?({:map, fields})

  defp tracked_value?(_), do: false

  defp branches_available?(count, values) do
    if budget = Process.get(@branch_budget_key) do
      if count > budget do
        if tracked_values?(values), do: mark_truncated(:alternative_limit)
        false
      else
        Process.put(@branch_budget_key, budget - count)
        true
      end
    else
      true
    end
  end

  defp mark_truncated(reason) do
    if reasons = Process.get(@truncated_key),
      do: Process.put(@truncated_key, MapSet.put(reasons, reason))
  end

  defp report_truncation(entry) do
    reasons = Process.get(@truncated_key, MapSet.new())

    if MapSet.size(reasons) > 0 do
      reasons =
        reasons
        |> Enum.sort()
        |> Enum.map_join(", ", fn reason -> reason |> to_string() |> String.replace("_", " ") end)

      IO.puts(
        :stderr,
        "WARNING: ETF handoff analysis for #{entry.filename} was incomplete (#{reasons})."
      )
    end
  end

  defp project_call({name, _, _} = call, values, locals, fun, extra)
       when is_atom(name) do
    signature = call_signature(call, extra)

    module =
      cond do
        Sobelow.Lexical.imported_module(call, signature) ->
          Sobelow.Lexical.imported_module(call, signature)

        Sobelow.Lexical.local_call?(call, extra) ->
          fun.module

        true ->
          nil
      end

    project_clauses(module, signature, values, locals, fun.module)
  end

  defp project_call({{:., _, [receiver, name]}, _, _} = call, values, locals, fun, _extra)
       when is_atom(name) do
    signature = {name, length(values)}

    modules =
      case Sobelow.Lexical.resolved_module(call) do
        module when is_list(module) -> [module]
        _ -> receiver_modules(receiver, locals, fun, values)
      end

    modules =
      if length(modules) > @max_clauses do
        if tracked_values?(values), do: mark_truncated(:alternative_limit)
        []
      else
        modules
      end

    results =
      for module <- modules,
          result = project_clauses(module, signature, values, locals, fun.module),
          result != nil,
          do: result

    case results do
      [] ->
        nil

      [{result, uses}] ->
        {result, uses}

      results ->
        {{:alternatives, Enum.map(results, &elem(&1, 0))}, Enum.flat_map(results, &elem(&1, 1))}
    end
  end

  defp project_call(_, _, _, _, _), do: nil

  defp receiver_modules({:__aliases__, _, _} = receiver, _locals, _fun, _values) do
    case Sobelow.Lexical.resolved_module(receiver) do
      module when is_list(module) -> [module]
      _ -> []
    end
  end

  defp receiver_modules({name, _, context}, locals, _fun, values)
       when is_atom(name) and is_atom(context) do
    # Evaluated by the caller's environment, not by a module loaded at scan time.
    locals |> Map.get(:receiver_env, %{}) |> Map.get(name) |> literal_modules(values)
  end

  defp receiver_modules(_, _, _, _), do: []

  defp literal_modules({:module, parts}, _values) when is_list(parts), do: [parts]

  defp literal_modules({:alternatives, options}, values) when length(options) <= @max_clauses do
    options |> Enum.flat_map(&literal_modules(&1, values)) |> Enum.uniq()
  end

  defp literal_modules({:alternatives, _}, values) do
    if tracked_values?(values), do: mark_truncated(:alternative_limit)
    []
  end

  defp literal_modules(_, _), do: []

  defp project_clauses(module, {name, arity}, values, locals, caller)
       when is_list(module) and is_atom(name) do
    clauses = project_definitions(locals.project, module, name, arity)

    if tracked_values?(values) do
      if MapSet.member?(locals.project.unresolved_defaults, {module, name, arity}),
        do: mark_truncated(:nonliteral_default)

      cond do
        length(clauses) > @max_clauses ->
          mark_truncated(:clause_limit)

        clauses != [] and Process.get(@budget_key, 0) < length(clauses) ->
          mark_truncated(:evaluation_limit)

        true ->
          :ok
      end
    end

    if clauses != [] and length(clauses) <= @max_clauses and
         Process.get(@budget_key, 0) >= length(clauses) and
         (module == caller or Enum.all?(clauses, fn {entry, _} -> entry.visibility == :def end)) do
      {results, uses} =
        Enum.map_reduce(clauses, [], fn {entry, defaults}, uses ->
          {result, more} =
            evaluate(
              entry,
              values ++ defaults,
              locals.project,
              locals.stack,
              locals.depth,
              false
            )

          {result, uses ++ more}
        end)

      case results do
        [result] -> {result, uses}
        _ -> {{:alternatives, results}, uses}
      end
    end
  end

  defp project_clauses(_, _, _, _, _), do: nil

  defp project_definitions(project, module, name, arity) do
    Map.get(project.functions, {module, name, arity}, [])
  end

  defp default_arguments(entry) do
    params = entry.fun |> elem(2) |> hd() |> head_params()
    params |> Enum.reverse() |> Enum.take_while(&match?({:\\, _, _}, &1)) |> Enum.reverse()
  end

  defp default_value({:\\, _, [_param, {:__aliases__, _, _} = literal]}, scope) do
    Sobelow.Lexical.with_context(scope, fn ->
      case Sobelow.Lexical.resolved_module(literal) do
        parts when is_list(parts) -> {:module, parts}
        _ -> nil
      end
    end)
  end

  defp default_value({:\\, _, [_param, literal]}, _scope), do: literal

  defp module_definitions({:__block__, _, nodes}, parent, filename, scopes, controllers, skips),
    do:
      Enum.flat_map(nodes, &module_definitions(&1, parent, filename, scopes, controllers, skips))

  defp module_definitions(
         {:defmodule, _, [{:__aliases__, _, parts}, [do: body]]},
         parent,
         filename,
         scopes,
         controllers,
         skips
       )
       when is_list(parts) do
    module = if List.first(parts) == :"Elixir", do: tl(parts), else: parent ++ parts

    if module != [] and Enum.all?(module, &is_atom/1) do
      body
      |> forms()
      |> Enum.flat_map(fn node ->
        case node do
          {visibility, _, [head | _]} = fun when visibility in [:def, :defp] ->
            case unguard(head) do
              {name, _, params} when is_atom(name) and is_list(params) ->
                key = Metadata.definition_key(fun)

                [
                  %{
                    module: module,
                    name: name,
                    arity: length(params),
                    filename: filename,
                    fun: fun,
                    visibility: visibility,
                    key: key,
                    scope: Map.get(scopes, key),
                    controller?: Map.get(controllers, key, false),
                    skips: Map.get(skips, key, [])
                  }
                ]

              _ ->
                []
            end

          _ ->
            module_definitions(node, module, filename, scopes, controllers, skips)
        end
      end)
    else
      []
    end
  end

  defp module_definitions(_, _, _, _, _, _), do: []
  defp forms({:__block__, _, nodes}), do: nodes
  defp forms(node), do: [node]
  defp unguard({:when, _, [head | _]}), do: head
  defp unguard(head), do: head

  # Only definitions in this lexical module participate. Multiple clauses of a
  # decoder wrapper are ambiguous; a scalar extractor is trusted only when *all*
  # its clauses return a guarded scalar (or a fixed rejection value).
  def local_functions(functions) do
    functions
    |> Enum.group_by(fn {entry, _lexical} -> signature(definition(entry)) end)
    |> Enum.reduce(%{wrappers: %{}, scalars: MapSet.new()}, fn
      {nil, _}, acc ->
        acc

      {signature, entries}, acc ->
        classify(entries, signature, acc)
    end)
  end

  def handoffs(fun, locals, controller?) do
    case fun do
      {kind, _, [head, [do: body]]} when kind in [:def, :defp] ->
        case head_params(head) do
          params when is_list(params) ->
            env =
              params
              |> Enum.reduce(%{}, fn
                {:conn, _, _}, env -> Map.put(env, :conn, @conn)
                {:params, _, _}, env when controller? -> Map.put(env, :params, @request)
                _, env -> env
              end)
              |> seed_resolver_args(kind, params)

            {_env, uses, _result} = walk(body, env, matches(fun), locals, fun, true)
            Enum.uniq_by(uses, fn {node, _origin, _source, _line} -> node end)

          _ ->
            []
        end

      _ ->
        []
    end
  end

  # An Absinthe resolver receives (parent, request arguments, resolution context).
  # Only a public three-argument resolver with an explicit context pattern has
  # enough evidence to treat its arguments as request-controlled.
  defp seed_resolver_args(env, :def, [_, {:args, _, context}, {:%{}, _, fields}])
       when is_atom(context) and is_list(fields) do
    if Enum.any?(fields, &match?({:context, _}, &1)),
      do: Map.put(env, :args, @request),
      else: env
  end

  defp seed_resolver_args(env, _, _), do: env

  defp head_params({:when, _, [head | _]}), do: head_params(head)
  defp head_params({_, _, params}), do: params
  defp head_params(_), do: nil

  defp seed_param({:=, _, [pattern, {name, _, context}]}, env, _controller?)
       when is_atom(name) and is_atom(context) do
    if plug_conn?(pattern) and name == :conn, do: Map.put(env, :conn, @conn), else: env
  end

  defp seed_param({:conn, _, _}, env, _), do: Map.put(env, :conn, @conn)
  defp seed_param({:params, _, _}, env, true), do: Map.put(env, :params, @request)
  defp seed_param(_, env, _), do: env

  defp plug_conn?({:%, _, [{:__aliases__, _, parts}, {:%{}, _, _}]}),
    do: parts in [[:Conn], [:Plug, :Conn]]

  defp plug_conn?(_), do: false

  defp definition({fun, _skips}), do: fun
  defp definition(fun), do: fun

  defp signature({kind, _, [{:when, _, [head | _]} | _]}) when kind in [:def, :defp],
    do: call_signature(head, 0)

  defp signature({kind, _, [head | _]}) when kind in [:def, :defp],
    do: call_signature(head, 0)

  defp signature(_), do: nil

  defp call_signature({name, _, args}, extra) when is_atom(name) and is_list(args),
    do: {name, length(args) + extra}

  defp call_signature({name, _, nil}, extra) when is_atom(name) and extra > 0,
    do: {name, extra}

  defp call_signature(_, _), do: nil

  defp classify([{entry, lexical}], signature, acc) do
    fun = definition(entry)

    Sobelow.Lexical.with_context(lexical, fn ->
      if wrapper = wrapper(fun),
        do: put_in(acc, [:wrappers, signature], wrapper),
        else: acc
    end)
  end

  defp classify(entries, signature, acc) do
    if Enum.all?(entries, fn {entry, lexical} ->
         Sobelow.Lexical.with_context(lexical, fn -> scalar_extractor?(definition(entry)) end)
       end),
       do: %{acc | scalars: MapSet.put(acc.scalars, signature)},
       else: acc
  end

  # A one-argument wrapper must return precisely the decoder result or {:ok,
  # result}; intermediate assignments are fine, but no other use is summarized.
  defp wrapper({kind, _, [{_name, _, [{param, _, context}]}, [do: body]]} = fun)
       when kind in [:def, :defp] and is_atom(param) and is_atom(context) do
    matches = matches(fun)
    {_env, uses, result} = walk(body, %{param => @request}, matches, empty_locals(), fun, false)

    case {uses, Map.keys(matches.decoder), result} do
      {[], [node], {:decoded, decoded, ^fun, _}} when node == decoded ->
        {node, fun, :direct}

      {[], [node], {:parts, [:ok, {:decoded, decoded, ^fun, _}]}} when node == decoded ->
        {node, fun, :ok}

      _ ->
        nil
    end
  end

  defp wrapper(_), do: nil
  defp empty_locals, do: %{wrappers: %{}, scalars: MapSet.new()}

  # Recognize the narrow, common cursor extractor: a map field is guarded as a
  # scalar, that scalar alone is returned, and every other clause has a literal
  # rejection. An arbitrary validator call is never taken as proof of safety.
  defp scalar_extractor?({kind, _, [head, [do: body]]}) when kind in [:def, :defp] do
    case head do
      {:when, _, [{_name, _, [{:%{}, _, [{_key, {field, _, context}}]}]}, guard]}
      when is_atom(field) and is_atom(context) ->
        scalar_guard?(guard, field) and scalar_result?(body, field)

      {_name, _, [{:_, _, _}]} ->
        Macro.quoted_literal?(body)

      _ ->
        false
    end
  end

  defp scalar_extractor?(_), do: false

  defp request_value?(@request), do: true
  defp request_value?(@conn), do: true
  defp request_value?({:conn_field, _}), do: true
  defp request_value?({:field, value}), do: request_value?(value)
  defp request_value?({:base64, source}), do: request_value?(source)
  defp request_value?({:parts, values}), do: Enum.any?(values, &request_value?/1)

  defp request_value?({:map, fields}),
    do: Enum.any?(fields, fn {_, value} -> request_value?(value) end)

  defp request_value?({:map_update, original, fields}),
    do: request_value?(original) or request_value?({:map, fields})

  defp request_value?({:alternatives, values}), do: Enum.any?(values, &request_value?/1)
  defp request_value?(_), do: false

  defp scalar_guard?({guard, _, [{field, _, context}]} = call, field)
       when guard in @scalar_guards and is_atom(context),
       do: Sobelow.Lexical.kernel_call?(call)

  defp scalar_guard?({guard, _, [left, right]}, field) when guard in [:and, :&&],
    do: scalar_guard?(left, field) or scalar_guard?(right, field)

  defp scalar_guard?(_, _), do: false
  defp scalar_result?({field, _, context}, field) when is_atom(context), do: true
  defp scalar_result?({:ok, {field, _, context}}, field) when is_atom(context), do: true
  defp scalar_result?({:{}, _, [:ok, {field, _, context}]}, field) when is_atom(context), do: true
  defp scalar_result?(_, _), do: false

  defp matches(fun) do
    %{
      decoder:
        Map.new(
          for {node, _, [_input, options]} <- Parse.calls_with_args(fun, @decoder),
              not match?({:&, _, _}, node),
              is_list(options) and :safe in options,
              do: {node, true}
        ),
      body: MapSet.new(for {node, _, _} <- Parse.calls_with_args(fun, @body_read), do: node),
      base64:
        Map.new(for {node, name, _} <- Parse.calls_with_args(fun, @base64), do: {node, name})
    }
  end

  defp walk({:__block__, _, statements}, env, matches, locals, fun, returning?) do
    last = length(statements) - 1

    statements
    |> Enum.with_index()
    |> Enum.reduce({env, [], nil}, fn {statement, index}, {env, uses, _result} ->
      {env, more, result} =
        walk(statement, env, matches, locals, fun, returning? and index == last)

      {env, uses ++ more, result}
    end)
  end

  defp walk(
         {operator, _, [pattern, expression]} = assignment,
         env,
         matches,
         locals,
         fun,
         returning?
       )
       when operator in [:=, :<-] do
    {env, uses, result} = walk(expression, env, matches, locals, fun, false)
    env = bind(pattern, result, env)
    uses = if returning?, do: uses ++ handoff(result, assignment), else: uses
    {env, uses, result}
  end

  defp walk({:with, _, parts} = with_node, env, matches, locals, fun, returning?) do
    case List.pop_at(parts, -1) do
      {options, clauses} when is_list(options) and is_list(clauses) ->
        {success_env, uses, failures} =
          Enum.reduce(clauses, {env, [], []}, fn
            {:<-, _, [pattern, expression]}, {env, uses, failures} ->
              {env, more, result} = walk(expression, env, matches, locals, fun, false)
              failures = if irrefutable?(pattern), do: failures, else: [result | failures]
              {checked_guard(pattern, bind(pattern, result, env)), uses ++ more, failures}

            clause, {env, uses, failures} ->
              {env, more, _} = walk(clause, env, matches, locals, fun, false)
              {env, uses ++ more, failures}
          end)

        {_env, success_uses, result} =
          walk(Keyword.get(options, :do), success_env, matches, locals, fun, returning?)

        else_clauses = Keyword.get(options, :else, [])

        paths = length(failures) * max(length(else_clauses), 1)

        if Map.has_key?(locals, :project) and
             (paths > @max_clauses or
                not branches_available?(paths, failures ++ Map.values(env))) do
          if paths > @max_clauses and
               (tracked_values?(failures) or tracked_values?(Map.values(env))),
             do: mark_truncated(:alternative_limit)

          {env, uses ++ success_uses, result}
        else
          else_results =
            for clause <- else_clauses,
                failure <- failures,
                do: branch(clause, failure, env, matches, locals, fun, returning?)

          failure_uses =
            if returning? and else_clauses == [],
              do: Enum.flat_map(failures, &handoff(&1, with_node)),
              else: []

          results =
            [result | Enum.map(else_results, &elem(&1, 1))] ++
              if(else_clauses == [], do: failures, else: [])

          {env, uses ++ success_uses ++ failure_uses ++ Enum.flat_map(else_results, &elem(&1, 0)),
           {:alternatives, results}}
        end

      _ ->
        {env, [], nil}
    end
  end

  defp walk({:case, _, [expression, options]}, env, matches, locals, fun, returning?)
       when is_list(options) do
    {env, uses, result} = walk(expression, env, matches, locals, fun, false)
    clauses = Keyword.get(options, :do, [])

    if Map.has_key?(locals, :project) and
         (length(clauses) > @max_clauses or
            not branches_available?(length(clauses), [result | Map.values(env)])) do
      if length(clauses) > @max_clauses and
           (tracked_value?(result) or tracked_values?(Map.values(env))),
         do: mark_truncated(:alternative_limit)

      {env, uses, nil}
    else
      results =
        for clause <- clauses,
            do: branch(clause, result, env, matches, locals, fun, returning?)

      {env, uses ++ Enum.flat_map(results, &elem(&1, 0)),
       {:alternatives, Enum.map(results, &elem(&1, 1))}}
    end
  end

  defp walk({:if, _, [condition, options]}, env, matches, locals, fun, returning?)
       when is_list(options) do
    {env, uses, _result} = walk(condition, env, matches, locals, fun, false)
    checked = checked_condition(condition, env)

    if Map.has_key?(locals, :project) and
         not branches_available?(2, Map.values(env)) do
      {env, uses, nil}
    else
      {_do_env, do_uses, do_result} =
        walk(Keyword.get(options, :do), checked, matches, locals, fun, returning?)

      {_else_env, else_uses, else_result} =
        walk(Keyword.get(options, :else), env, matches, locals, fun, returning?)

      # Elixir branch assignments are scoped to the branch; only the condition
      # can rebind variables in the surrounding function.
      {env, uses ++ do_uses ++ else_uses, {:alternatives, [do_result, else_result]}}
    end
  end

  defp walk(expression, env, matches, locals, fun, returning?) do
    {result, uses} = value(expression, env, matches, locals, fun)
    uses = if returning?, do: uses ++ handoff(result, expression), else: uses
    {env, uses, result}
  end

  defp branch(clause, {:alternatives, values}, env, matches, locals, fun, returning?)
       when length(values) <= @max_clauses do
    if Map.has_key?(locals, :project) and
         not branches_available?(length(values), values ++ Map.values(env)) do
      {[], nil}
    else
      results = Enum.map(values, &branch(clause, &1, env, matches, locals, fun, returning?))

      {Enum.flat_map(results, &elem(&1, 0)), {:alternatives, Enum.map(results, &elem(&1, 1))}}
    end
  end

  defp branch(_clause, {:alternatives, values}, _env, _matches, _locals, _fun, _returning?) do
    if tracked_values?(values), do: mark_truncated(:alternative_limit)
    {[], nil}
  end

  defp branch({:->, _, [[pattern], body]}, result, env, matches, locals, fun, returning?) do
    env = checked_guard(pattern, bind(pattern, result, env))
    {_env, uses, value} = walk(body, env, matches, locals, fun, returning?)
    {uses, value}
  end

  defp branch(_, _, _, _, _, _, _), do: {[], nil}

  defp irrefutable?({name, _, context}) when is_atom(name) and is_atom(context), do: true
  defp irrefutable?({:=, _, [left, right]}), do: irrefutable?(left) and irrefutable?(right)
  defp irrefutable?(_), do: false

  defp checked_guard({:when, _, [_pattern, guard]}, env), do: checked_condition(guard, env)
  defp checked_guard(_, env), do: env

  defp checked_condition({guard, _, [subject]} = call, env) when guard in @scalar_guards do
    if Sobelow.Lexical.kernel_call?(call) do
      case subject do
        {name, _, context} when is_atom(name) and is_atom(context) ->
          # Checking the encoded request body does not validate the decoded term.
          if request_value?(Map.get(env, name)),
            do: env,
            else: clear_guards(env, name) |> Map.delete(name)

        _ ->
          case field_key(subject) do
            {name, _} = key ->
              # A guard on conn.params["cursor"] validates only the encoded
              # bytes, not the decoded ETF term produced from those bytes.
              if request_value?(Map.get(env, name)),
                do: env,
                else: Map.put(env, {:guarded_field, key}, true)

            nil ->
              env
          end
      end
    else
      env
    end
  end

  defp checked_condition({operator, _, [left, right]}, env) when operator in [:and, :&&],
    do: checked_condition(right, checked_condition(left, env))

  defp checked_condition(_, env), do: env

  defp field_key({name, _, context}) when is_atom(name) and is_atom(context), do: {name, []}

  defp field_key({{:., _, [Access, :get]}, _, [receiver, key]})
       when is_atom(key) or is_binary(key) or is_integer(key),
       do: append_field(receiver, key)

  defp field_key({{:., _, [receiver, key]}, _, []}) when is_atom(key),
    do: append_field(receiver, key)

  defp field_key(_), do: nil

  defp append_field(receiver, key) do
    case field_key(receiver) do
      {name, path} -> {name, path ++ [key]}
      nil -> nil
    end
  end

  defp clear_guards(env, name) do
    Enum.reduce(Map.keys(env), env, fn
      {:guarded_field, {^name, _}} = key, acc -> Map.delete(acc, key)
      _, acc -> acc
    end)
  end

  defp selected_field(result, expression, env) do
    if Map.get(env, {:guarded_field, field_key(expression)}), do: nil, else: result
  end

  defp bind(pattern, {:alternatives, values}, env) when length(values) <= @max_clauses do
    names = pattern_names(pattern)
    bound = Enum.map(values, &bind(pattern, &1, env))

    Enum.reduce(names, env, fn name, acc ->
      alternatives = Enum.map(bound, &Map.get(&1, name))
      Map.put(clear_guards(acc, name), name, {:alternatives, alternatives})
    end)
  end

  defp bind(pattern, {:alternatives, values}, env) do
    if tracked_values?(values), do: mark_truncated(:alternative_limit)
    bind(pattern, nil, env)
  end

  defp bind({:\\, _, [pattern, _default]}, result, env), do: bind(pattern, result, env)
  defp bind({:when, _, [pattern | _]}, result, env), do: bind(pattern, result, env)
  defp bind({:=, _, [left, right]}, result, env), do: bind(right, result, bind(left, result, env))

  defp bind({name, _, context}, result, env) when is_atom(name) and is_atom(context) do
    if name == :_, do: env, else: Map.put(clear_guards(env, name), name, result)
  end

  defp bind({:{}, _, patterns}, {:parts, results}, env)
       when length(patterns) == length(results) do
    bind_parts(patterns, results, env)
  end

  defp bind({:{}, _, patterns}, _result, env), do: bind_parts(patterns, [], env)

  defp bind(patterns, {:parts, results}, env)
       when is_list(patterns) and length(patterns) == length(results),
       do: bind_parts(patterns, results, env)

  defp bind(patterns, _result, env) when is_list(patterns), do: bind_parts(patterns, [], env)

  defp bind({left, right}, {:parts, [a, b]}, env) do
    env = bind(left, a, env)
    bind(right, b, env)
  end

  defp bind({left, right}, _result, env), do: bind(right, nil, bind(left, nil, env))

  defp bind({:%{}, _, fields}, result, env) do
    Enum.reduce(fields, env, fn {key, pattern}, env ->
      bind(pattern, select_field(result, key), env)
    end)
  end

  defp bind(_pattern, _result, env), do: env

  defp pattern_names(pattern) do
    {_pattern, names} =
      Macro.prewalk(pattern, MapSet.new(), fn
        {name, _, context} = node, acc when is_atom(name) and is_atom(context) and name != :_ ->
          {node, MapSet.put(acc, name)}

        node, acc ->
          {node, acc}
      end)

    MapSet.to_list(names)
  end

  defp bind_parts(patterns, results, env) do
    patterns
    |> Enum.zip(results ++ List.duplicate(nil, length(patterns)))
    |> Enum.reduce(env, fn {pattern, result}, env -> bind(pattern, result, env) end)
  end

  defp select_field({:alternatives, values}, key),
    do: {:alternatives, Enum.map(values, &select_field(&1, key))}

  defp select_field(result, _key) when result == @request, do: @request

  defp select_field({:map, fields}, key) do
    case List.keyfind(fields, key, 0) do
      {_, result} -> result
      nil -> nil
    end
  end

  defp select_field({:map_update, original, fields}, key) do
    case List.keyfind(fields, key, 0) do
      {_, result} -> result
      nil -> select_field(original, key)
    end
  end

  defp select_field(nil, _key), do: nil
  defp select_field(result, _key), do: field(result)

  defp field(value), do: {:field, value}

  defp value({:__aliases__, _, parts} = alias_node, _env, _matches, _locals, _fun)
       when is_list(parts) do
    case Sobelow.Lexical.resolved_module(alias_node) do
      module when is_list(module) -> {{:module, module}, []}
      _ -> {nil, []}
    end
  end

  defp value({name, _, context}, env, _matches, _locals, _fun)
       when is_atom(name) and is_atom(context), do: {Map.get(env, name), []}

  defp value({:{}, _, items}, env, matches, locals, fun),
    do: parts(items, env, matches, locals, fun)

  defp value({left, right}, env, matches, locals, fun),
    do: parts([left, right], env, matches, locals, fun)

  defp value({:%{}, _, [{:|, _, [original, updates]}]}, env, matches, locals, fun) do
    {result, uses} = value(original, env, matches, locals, fun)
    {updates, more} = map_fields(updates, env, matches, locals, fun)
    {{:map_update, result, updates}, uses ++ more}
  end

  defp value({:%{}, _, fields}, env, matches, locals, fun) do
    {fields, uses} = map_fields(fields, env, matches, locals, fun)
    {{:map, fields}, uses}
  end

  defp value(items, env, matches, locals, fun) when is_list(items),
    do: parts(items, env, matches, locals, fun)

  defp value({:|>, _, [input, call]}, env, matches, locals, fun) do
    {piped, uses} = value(input, env, matches, locals, fun)
    {result, more} = call_value(call, env, matches, locals, fun, piped)
    {result, uses ++ more}
  end

  defp value({{:., _, [receiver, name]}, _, []} = call, env, matches, locals, fun) do
    {result, uses} = value(receiver, env, matches, locals, fun)

    cond do
      name in [:params, :body_params] and result == @conn -> {@request, uses}
      result == @request -> {@request, uses}
      result != nil -> {selected_field(select_field(result, name), call, env), uses}
      true -> call_value(call, env, matches, locals, fun, @none)
    end
  end

  defp value({{:., _, [Access, :get]}, _, [receiver, key]} = access, env, matches, locals, fun) do
    {result, uses} = value(receiver, env, matches, locals, fun)
    {selected_field(select_field(result, key), access, env), uses}
  end

  defp value({kind, _, _} = expression, env, matches, locals, fun)
       when kind in [:if, :case, :with, :__block__, :=] do
    {_env, uses, result} = walk(expression, env, matches, locals, fun, false)
    {result, uses}
  end

  defp value({_, _, args} = call, env, matches, locals, fun) when is_list(args),
    do: call_value(call, env, matches, locals, fun, @none)

  defp value(literal, _env, _matches, _locals, _fun), do: {literal, []}

  defp map_fields(fields, env, matches, locals, fun) do
    Enum.map_reduce(fields, [], fn {key, item}, uses ->
      {result, more} = value(item, env, matches, locals, fun)
      {{key, result}, uses ++ more}
    end)
  end

  defp parts(items, env, matches, locals, fun) do
    {results, uses} =
      Enum.map_reduce(items, [], fn item, uses ->
        {result, more} = value(item, env, matches, locals, fun)
        {result, uses ++ more}
      end)

    {{:parts, results}, uses}
  end

  defp call_value({_, _, args} = call, env, matches, locals, fun, piped)
       when is_list(args) or is_nil(args) do
    {{:parts, values}, uses} = parts(args || [], env, matches, locals, fun)
    values = if piped == @none, do: values, else: [piped | values]
    source = List.first(values)
    signature = call_signature(call, if(piped == @none, do: 0, else: 1))

    cond do
      Map.has_key?(matches.decoder, call) ->
        {decode(source, call, fun), uses}

      MapSet.member?(matches.body, call) and source == @conn ->
        {{:parts, [:ok, @request, @conn]}, uses}

      Map.has_key?(matches.base64, call) ->
        result =
          if matches.base64[call] in [:decode64, :url_decode64],
            do: {:parts, [:ok, source]},
            else: source

        {result, uses}

      Map.has_key?(locals.wrappers, signature) and
          Sobelow.Lexical.local_call?(call, if(piped == @none, do: 0, else: 1)) ->
        {node, origin, shape} = Map.fetch!(locals.wrappers, signature)
        decoded = decode(source, node, origin)
        {if(shape == :ok, do: {:parts, [:ok, decoded]}, else: decoded), uses}

      MapSet.member?(locals.scalars, signature) and
          Sobelow.Lexical.local_call?(call, if(piped == @none, do: 0, else: 1)) ->
        {nil, uses}

      pure_check?(call) ->
        {nil, uses}

      true ->
        case project_result(call, values, env, locals, fun, piped) do
          {result, more} -> {result, uses ++ more}
          nil -> {nil, uses ++ Enum.flat_map(values, &handoff(&1, call))}
        end
    end
  end

  defp call_value(_call, _env, _matches, _locals, _fun, _piped), do: {nil, []}

  defp project_result(_call, _values, _env, %{project: project}, fun, _piped)
       when not is_map(project) or not is_map(fun), do: nil

  defp project_result(call, values, env, %{project: _} = locals, fun, piped) do
    extra = if piped == @none, do: 0, else: 1
    project_call(call, values, Map.put(locals, :receiver_env, env), fun, extra)
  end

  defp project_result(_call, _values, _env, _locals, _fun, _piped), do: nil

  defp pure_check?({name, _, _} = call)
       when name in @scalar_guards or name in [:is_map, :is_list, :match?],
       do: Sobelow.Lexical.kernel_call?(call)

  defp pure_check?(_), do: false

  defp decode({:alternatives, values}, node, fun) when length(values) <= @max_clauses,
    do: {:alternatives, Enum.map(values, &decode(&1, node, fun))}

  defp decode({:alternatives, values}, _node, _fun) do
    if tracked_values?(values), do: mark_truncated(:alternative_limit)
    nil
  end

  defp decode(source, node, fun) when source == @request,
    do: {:decoded, node, fun, "request input"}

  defp decode(_, _, _), do: nil

  defp handoff(value, use) do
    line = use_line(use)
    for {node, fun, source} <- decoded(value), do: {node, fun, source, line}
  end

  defp use_line({_, meta, _}) when is_list(meta), do: Keyword.get(meta, :line, 0)

  defp use_line(use) do
    {_use, lines} =
      Macro.prewalk(use, [], fn
        {_, meta, _} = node, lines when is_list(meta) ->
          {node, [Keyword.get(meta, :line, 0) | lines]}

        node, lines ->
          {node, lines}
      end)

    List.last(lines) || 0
  end

  defp decoded({:decoded, node, fun, source}), do: [{node, fun, source}]
  defp decoded({:field, value}), do: decoded(value)
  defp decoded({:map, fields}), do: Enum.flat_map(fields, fn {_key, value} -> decoded(value) end)

  defp decoded({:map_update, original, fields}) do
    replaced = Enum.map(fields, &elem(&1, 0))
    decoded_original(original, replaced) ++ decoded({:map, fields})
  end

  defp decoded({:parts, values}), do: Enum.flat_map(values, &decoded/1)
  defp decoded({:alternatives, values}), do: Enum.flat_map(values, &decoded/1)
  defp decoded(_), do: []

  defp decoded_original({:map, fields}, replaced) do
    fields = Enum.reject(fields, fn {key, _value} -> key in replaced end)
    decoded({:map, fields})
  end

  defp decoded_original({:map_update, original, fields}, replaced) do
    fields = Enum.reject(fields, fn {key, _value} -> key in replaced end)

    decoded_original(original, replaced ++ Enum.map(fields, &elem(&1, 0))) ++
      decoded({:map, fields})
  end

  defp decoded_original(original, _replaced), do: decoded(original)
end
