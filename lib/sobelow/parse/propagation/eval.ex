defmodule Sobelow.Parse.Propagation.Eval do
  @moduledoc false

  alias Sobelow.Lexical

  @max_depth 5
  @max_clauses 12
  @max_work 256

  # The caller supplies a source label; nothing in this layer knows what kind
  # of data it represents or which consumer is dangerous. Results are always
  # independent of output format and the evidence-only Parse.Flow traversal.
  def run(project, signature, arguments, opts) do
    state = %{
      work: Keyword.get(opts, :max_work, @max_work),
      consumers: [],
      truncated: MapSet.new()
    }

    {returns, state} = invoke(project, signature, arguments, nil, [], state)

    %{
      returns: returns,
      consumers: Enum.reverse(state.consumers),
      truncated: state.truncated
    }
  end

  defp invoke(project, signature, arguments, caller, stack, state) do
    clauses = Map.get(project.functions, signature, [])

    state =
      if MapSet.member?(project.unresolved_defaults, signature) and tracked?(arguments),
        do: truncate(state, :nonliteral_default),
        else: state

    cond do
      signature in stack ->
        {opaque(arguments), maybe_truncate(state, :recursive_call, arguments)}

      length(stack) >= @max_depth ->
        {opaque(arguments), maybe_truncate(state, :depth_limit, arguments)}

      length(clauses) > @max_clauses ->
        {opaque(arguments), maybe_truncate(state, :clause_limit, arguments)}

      clauses == [] ->
        {opaque(arguments), maybe_truncate(state, :unresolved_call, arguments)}

      length(clauses) > state.work ->
        {opaque(arguments), maybe_truncate(state, :work_limit, arguments)}

      true ->
        {values, state} =
          Enum.reduce(clauses, {[], state}, fn {entry, defaults, declaration}, {values, state} ->
            if (caller == nil or entry.module == caller or entry.visibility == :def) and
                 match?({:ok, _}, entry.body) and state.work > 0 do
              {defaults, state} =
                Lexical.with_context(declaration.scope, fn ->
                  Enum.map_reduce(defaults, state, fn default, state ->
                    {value, _env, state} = eval(default, %{}, entry, project, stack, state)
                    {value, state}
                  end)
                end)

              state =
                if Enum.any?(defaults, &match?({:module, nil}, &1)),
                  do: maybe_truncate(state, :nonliteral_default, arguments),
                  else: state

              bindings =
                declaration.params
                |> align_arguments(arguments, defaults)
                |> then_bind(entry.params)

              {:ok, body} = entry.body
              state = %{state | work: state.work - 1}

              {result, state} =
                Lexical.with_context(entry.scope, fn ->
                  {result, _env, state} =
                    eval(
                      body,
                      guard(entry.head, bindings),
                      entry,
                      project,
                      [signature | stack],
                      state
                    )

                  {result, state}
                end)

              {values ++ alternatives(result), state}
            else
              state =
                if state.work <= 0 and tracked?(arguments),
                  do: truncate(state, :work_limit),
                  else: state

              {values, state}
            end
          end)

        values =
          if MapSet.member?(project.unresolved_defaults, signature),
            do: values ++ opaque(arguments),
            else: values

        {values, state}
    end
  end

  defp eval({:__block__, _, nodes}, env, entry, project, stack, state) do
    Enum.reduce(nodes, {nil, env, state}, fn node, {_result, env, state} ->
      eval(node, env, entry, project, stack, state)
    end)
  end

  defp eval({:=, _, [pattern, rhs]}, env, entry, project, stack, state) do
    {value, env, state} = eval(rhs, env, entry, project, stack, state)
    {value, bind(pattern, value, env), state}
  end

  defp eval({:if, _, [condition, options]}, env, entry, project, stack, state)
       when is_list(options) do
    {condition_value, env, state} = eval(condition, env, entry, project, stack, state)
    possible_sources = [condition_value | Map.values(env)]
    state = spend(state, 2, possible_sources)

    if state.work < 0 do
      {List.first(opaque(possible_sources)), env, state}
    else
      {yes, _env, state} =
        eval(Keyword.get(options, :do), guard(condition, env), entry, project, stack, state)

      {no, _env, state} =
        eval(Keyword.get(options, :else), env, entry, project, stack, state)

      {value, state} = combine([yes, no], state)
      {value, env, state}
    end
  end

  defp eval({:case, _, [subject, [do: clauses]]}, env, entry, project, stack, state)
       when is_list(clauses) do
    {value, env, state} = eval(subject, env, entry, project, stack, state)
    branch_clauses(clauses, value, env, entry, project, stack, state)
  end

  defp eval({:with, _, clauses}, env, entry, project, stack, state) when is_list(clauses) do
    {options, steps} = List.pop_at(clauses, -1)

    if is_list(options) and Keyword.keyword?(options) do
      {inner, failures, state} =
        Enum.reduce(steps, {env, [], state}, fn
          {:<-, _, [pattern, rhs]}, {inner, failures, state} ->
            {value, inner, state} = eval(rhs, inner, entry, project, stack, state)
            {guard(pattern, bind(pattern, value, inner)), [value | failures], state}

          node, {inner, failures, state} ->
            {_value, inner, state} = eval(node, inner, entry, project, stack, state)
            {inner, failures, state}
        end)

      {success, _inner, state} =
        eval(Keyword.get(options, :do), inner, entry, project, stack, state)

      {failed, state} =
        Enum.reduce(failures, {[], state}, fn value, {results, state} ->
          {result, _inner, state} =
            branch_clauses(
              Keyword.get(options, :else, []),
              value,
              env,
              entry,
              project,
              stack,
              state
            )

          {results ++ alternatives(result), state}
        end)

      # An else need not match every failed step. Keep the failed RHS as a
      # possible value rather than silently treating that path as harmless.
      alternatives = [success | failed ++ failures]

      {value, state} = combine(alternatives, state)
      {value, env, state}
    else
      {nil, env, state}
    end
  end

  defp eval(values, env, entry, project, stack, state) when is_list(values) do
    {values, state} =
      Enum.map_reduce(values, state, fn value, state ->
        {value, _inner, state} = eval(value, env, entry, project, stack, state)
        {value, state}
      end)

    {{:list, values}, env, state}
  end

  defp eval({:%{}, _, [{:|, _, [original, changes]}]}, env, entry, project, stack, state)
       when is_list(changes) do
    {original, _inner, state} = eval(original, env, entry, project, stack, state)
    {changes, _inner, state} = eval({:%{}, [], changes}, env, entry, project, stack, state)
    {update_map(original, changes), env, state}
  end

  defp eval({:%{}, _, fields}, env, entry, project, stack, state) when is_list(fields) do
    {fields, state} =
      Enum.map_reduce(fields, state, fn
        {key, rhs}, state when is_atom(key) or is_binary(key) or is_integer(key) ->
          {value, _inner, state} = eval(rhs, env, entry, project, stack, state)
          {{key, value}, state}

        {key, rhs}, state ->
          {key_value, _inner, state} = eval(key, env, entry, project, stack, state)
          {value, _inner, state} = eval(rhs, env, entry, project, stack, state)
          {{:unknown_key, {:unknown, [key_value, value]}}, state}
      end)

    {{:map, fields}, env, state}
  end

  # Elixir quotes two-element tuple literals directly, without a :{} AST tag.
  defp eval({left, right}, env, entry, project, stack, state) do
    {left, _inner, state} = eval(left, env, entry, project, stack, state)
    {right, _inner, state} = eval(right, env, entry, project, stack, state)
    {{:tuple, [left, right]}, env, state}
  end

  defp eval({:{}, _, fields}, env, entry, project, stack, state) when is_list(fields) do
    {values, state} =
      Enum.map_reduce(fields, state, fn field, state ->
        {value, _env, state} = eval(field, env, entry, project, stack, state)
        {value, state}
      end)

    {{:tuple, values}, env, state}
  end

  defp eval({{:., _, [Access, :get]}, _, [obj, key]}, env, entry, project, stack, state)
       when is_atom(key) or is_binary(key) do
    {value, env, state} = eval(obj, env, entry, project, stack, state)
    {field(value, key), env, state}
  end

  defp eval({{:., _, [obj, field_name]}, meta, []} = call, env, entry, project, stack, state) do
    if meta[:no_parens] and not match?({:__aliases__, _, _}, obj) do
      {value, env, state} = eval(obj, env, entry, project, stack, state)
      {field(value, field_name), env, state}
    else
      invoke_call(call, [], env, entry, project, stack, state)
    end
  end

  defp eval({:|>, _, [input, {_, _, args} = call]}, env, entry, project, stack, state)
       when is_list(args) or is_nil(args) do
    invoke_call(call, [input | args || []], env, entry, project, stack, state)
  end

  defp eval({:__aliases__, _, _} = node, env, _entry, _project, _stack, state),
    do: {{:module, Lexical.resolved_module(node)}, env, state}

  defp eval({name, _, context}, env, _entry, _project, _stack, state)
       when is_atom(name) and is_atom(context), do: {Map.get(env, name), env, state}

  defp eval({_, _, args} = node, env, entry, project, stack, state) when is_list(args),
    do: invoke_call(node, args, env, entry, project, stack, state)

  defp eval(value, env, _entry, _project, _stack, state), do: {value, env, state}

  defp update_map({:map, original}, {:map, changes}) do
    {:map, Map.to_list(Map.merge(Map.new(original), Map.new(changes)))}
  end

  defp update_map(original, changes), do: {:unknown, [original, changes]}

  defp branch_clauses(clauses, value, env, entry, project, stack, state) do
    state = spend(state, length(clauses), [value | Map.values(env)])

    if length(clauses) > @max_clauses or state.work < 0 do
      reason = if length(clauses) > @max_clauses, do: :clause_limit, else: :work_limit
      possible_sources = [value | Map.values(env)]
      {List.first(opaque(possible_sources)), env, maybe_truncate(state, reason, possible_sources)}
    else
      {results, state} =
        Enum.map_reduce(clauses, state, fn
          {:->, _, [patterns, body]}, state when is_list(patterns) ->
            bindings = Enum.reduce(patterns, env, &bind(&1, value, &2))
            {result, _inner, state} = eval(body, bindings, entry, project, stack, state)
            {result, state}

          _, state ->
            {nil, maybe_truncate(state, :unknown_clause, [value])}
        end)

      {result, state} = combine(results, state)
      {result, env, state}
    end
  end

  defp invoke_call(node, args, env, entry, project, stack, state) do
    {values, state} =
      Enum.map_reduce(args, state, fn argument, state ->
        {value, _inner, state} = eval(argument, env, entry, project, stack, state)
        {value, state}
      end)

    signatures = targets(node, values, env, entry, project)

    if length(signatures) > @max_clauses do
      {result, state} = unknown_call(node, values, entry, state)
      {List.first(result), env, maybe_truncate(state, :alternative_limit, values)}
    else
      resolve_call(signatures, node, values, env, entry, project, stack, state)
    end
  end

  defp resolve_call(signatures, node, values, env, entry, project, stack, state) do
    if signatures == [] do
      {result, state} = unknown_call(node, values, entry, state)
      {List.first(result), env, state}
    else
      state = spend(state, length(signatures), values)

      {results, state} =
        Enum.map_reduce(signatures, state, fn
          :unknown, state ->
            {_results, state} = unknown_call(node, values, entry, state)
            {[], maybe_truncate(state, :dynamic_receiver, values)}

          signature, state ->
            if state.work < 0,
              do: {opaque(values), maybe_truncate(state, :work_limit, values)},
              else: invoke(project, signature, values, entry.module, stack, state)
        end)

      unknown = if :unknown in signatures and tracked?(values), do: [{:unknown, values}], else: []
      {result, state} = combine(Enum.concat(results) ++ unknown, state)
      {result, env, state}
    end
  end

  defp unknown_call(node, values, entry, state) do
    if tracked?(values) do
      {[{:unknown, values}], %{state | consumers: [{node, values, entry} | state.consumers]}}
    else
      {[], state}
    end
  end

  defp targets({name, _, _} = node, args, _env, entry, project) when is_atom(name) do
    arity = length(args)
    key = {entry.module, name, arity}
    imported = Lexical.imported_module(node, {name, arity})

    key =
      if imported != nil and not Map.has_key?(project.functions, key),
        do: {imported, name, arity},
        else: key

    if visible?(project, key, entry.module), do: [key], else: []
  end

  defp targets({{:., _, [receiver, name]}, _, _} = node, args, env, entry, project)
       when is_atom(name) do
    modules =
      case Lexical.resolved_module(node) do
        module when is_list(module) ->
          nested = entry.module ++ module

          if Map.has_key?(project.functions, {nested, name, length(args)}),
            do: [nested],
            else: [module]

        _ ->
          module_values(receiver, env)
      end

    for module <- modules do
      key = {module, name, length(args)}

      cond do
        module == :unknown -> :unknown
        visible?(project, key, entry.module) -> key
        true -> nil
      end
    end
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp targets(_, _, _, _, _), do: []

  defp visible?(project, key, caller) do
    Enum.any?(Map.get(project.functions, key, []), fn {entry, _defaults, _scope} ->
      entry.visibility == :def or entry.module == caller
    end)
  end

  defp module_values({name, _, context}, env) when is_atom(name) and is_atom(context) do
    case Map.get(env, name) do
      {:module, parts} when is_list(parts) ->
        [parts]

      {:choices, values} ->
        Enum.map(values, fn
          {:module, parts} when is_list(parts) -> parts
          _ -> :unknown
        end)

      _ ->
        [:unknown]
    end
  end

  defp module_values(_, _), do: []

  defp align_arguments(params, arguments, defaults) do
    omitted = length(params) - length(arguments)

    {values, [], []} =
      Enum.reduce(params, {[], arguments, defaults}, fn parameter, {values, args, defaults} ->
        if match?({:\\, _, _}, parameter) and
             Enum.count(values, &match?({:default, _}, &1)) < omitted do
          [default | rest] = defaults
          {[{:default, default} | values], args, rest}
        else
          [value | rest] = args
          {[{:provided, value} | values], rest, defaults}
        end
      end)

    Enum.reverse(values) |> Enum.map(fn {_kind, value} -> value end)
  end

  defp then_bind(values, params) do
    Enum.zip(params, values)
    |> Enum.reduce(%{}, fn {pattern, value}, env -> bind(parameter(pattern), value, env) end)
  end

  defp parameter({:\\, _, [pattern, _]}), do: pattern
  defp parameter(pattern), do: pattern

  defp bind({:when, _, [pattern | _]}, value, env), do: bind(pattern, value, env)

  defp bind({:=, _, [left, right]}, value, env) do
    env = bind(left, value, env)
    bind(right, value, env)
  end

  defp bind({:\\, _, [pattern, _]}, value, env), do: bind(pattern, value, env)

  defp bind({name, _, context}, value, env) when is_atom(name) and is_atom(context),
    do: if(name == :_, do: env, else: Map.put(env, name, value))

  defp bind({:%{}, _, fields}, value, env) do
    Enum.reduce(fields, env, fn {key, pattern}, bindings ->
      bind(pattern, field(value, key), bindings)
    end)
  end

  defp bind({left, right}, value, env) do
    env = bind(left, field(value, 0), env)
    bind(right, field(value, 1), env)
  end

  defp bind({:{}, _, patterns}, value, env) do
    Enum.reduce(Enum.with_index(patterns), env, fn {pattern, index}, bindings ->
      bind(pattern, field(value, index), bindings)
    end)
  end

  defp bind(patterns, value, env) when is_list(patterns) do
    Enum.reduce(Enum.with_index(patterns), env, fn {pattern, index}, bindings ->
      bind(pattern, field(value, index), bindings)
    end)
  end

  defp bind(_, _, env), do: env

  # A scalar guard is not validation of trust. In particular a source that
  # happens to be an integer remains a source. Security policy belongs to the
  # integration, not to the reusable propagation representation.
  defp guard(_condition, env), do: env

  defp field({:choices, values}, key), do: union(Enum.map(values, &field(&1, key)))

  defp field({:map, fields}, key) do
    known = for {field_key, value} <- fields, field_key != :unknown_key, do: {field_key, value}
    value = Map.get(Map.new(known), key)
    unknown = for {:unknown_key, source} <- fields, do: source
    union([value | unknown])
  end

  defp field({:tuple, fields}, key) when is_integer(key), do: Enum.at(fields, key)
  defp field({:list, fields}, key) when is_integer(key), do: Enum.at(fields, key)
  defp field({:source, _} = source, _), do: source
  defp field({:unknown, values}, _key), do: {:unknown, values}
  defp field(_, _), do: nil

  defp opaque(values), do: if(tracked?(values), do: [{:unknown, values}], else: [])

  defp alternatives({:choices, values}), do: values
  defp alternatives(nil), do: []
  defp alternatives(value), do: [value]

  defp union(values) do
    choices =
      values
      |> Enum.flat_map(fn
        {:choices, branches} -> branches
        branch -> [branch]
      end)
      |> Enum.uniq()

    case choices do
      [value] -> value
      [] -> nil
      _ -> {:choices, choices}
    end
  end

  defp combine(values, state) do
    choices =
      Enum.flat_map(values, fn
        {:choices, branches} -> branches
        branch -> [branch]
      end)

    if length(Enum.uniq(choices)) > @max_clauses do
      # Retain every tracked alternative even when precise branching exceeds
      # the budget; a take-first cap could otherwise drop a late source.
      {{:unknown, choices}, maybe_truncate(state, :alternative_limit, choices)}
    else
      {union(values), state}
    end
  end

  defp tracked?({:choices, values}), do: tracked?(values)
  defp tracked?(values) when is_list(values), do: Enum.any?(values, &tracked?/1)
  defp tracked?({:source, _}), do: true
  defp tracked?({:unknown, values}), do: tracked?(values)
  defp tracked?({:map, fields}), do: Enum.any?(fields, fn {_, value} -> tracked?(value) end)
  defp tracked?({:tuple, values}), do: tracked?(values)
  defp tracked?({:list, values}), do: tracked?(values)
  defp tracked?(_), do: false

  defp spend(state, count, values) do
    if count > state.work and tracked?(values),
      do: truncate(%{state | work: -1}, :work_limit),
      else: %{state | work: state.work - count}
  end

  defp maybe_truncate(state, reason, values) do
    if tracked?(values), do: truncate(state, reason), else: state
  end

  defp truncate(state, reason), do: %{state | truncated: MapSet.put(state.truncated, reason)}
end
