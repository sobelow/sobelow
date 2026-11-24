defmodule Sobelow.Parse.Flow.Eval do
  @moduledoc false

  alias Sobelow.{Finding, Lexical}
  alias Sobelow.Parse.Flow.{Branches, LiveView, Pattern, Value}
  alias Sobelow.Traversal.FileModule

  def entry(%{visibility: :def, body: {:ok, body}} = fun, functions, {flows, sockets}) do
    case inputs(fun) do
      nil ->
        {flows, sockets}

      inputs ->
        env = bind_params(fun.params, inputs)

        ctx = %{
          fun: fun,
          functions: functions,
          stack: [{fun.module, fun.name, fun.arity}],
          source: site(fun, fun.head, "#{fun.name}/#{fun.arity} receives request data")
        }

        {result, _, state} =
          Lexical.with_context(fun.scope, fn ->
            eval(body, env, ctx, %{flows: flows, fuel: 256})
          end)

        {state.flows, LiveView.returned(fun, result, sockets)}
    end
  end

  def entry(_, _, acc), do: acc

  defp inputs(%{kind: :controller, arity: 2}) do
    fields =
      for key <- [:params, :query_params, :body_params, :path_params], do: {key, Value.input()}

    [Value.aggregate(:map, fields), Value.input()]
  end

  defp inputs(%{kind: :live_view, name: :handle_event, arity: 3} = fun) do
    payload =
      Value.step(Value.input(), site(fun, fun.head, "handle_event/3 receives the event payload"))

    [Value.unknown(), payload, Value.aggregate(:socket, [{:assigns, Value.tag(:map)}])]
  end

  defp inputs(_), do: nil

  defp bind_params(patterns, values) do
    Enum.zip(patterns, values) |> Enum.reduce(%{}, fn {p, v}, env -> Pattern.bind(p, v, env) end)
  end

  def site(fun, node, text), do: Finding.flow_location(fun.file, node, text)

  def eval({:__block__, _, forms}, env, ctx, st) when is_list(forms) do
    Enum.reduce_while(forms, {Value.unknown(), env, st}, fn form, {_, vars, acc} ->
      case eval(form, vars, ctx, acc) do
        {[], _, _} = stop -> {:halt, stop}
        next -> {:cont, next}
      end
    end)
  end

  def eval({:=, _, [pat, rhs]} = node, env, ctx, st) do
    {value, env, st} = eval(rhs, env, ctx, st)
    value = Enum.reject(value, &(Value.known?(&1, pat) == :no))
    value = Value.step(value, site(ctx.fun, node, "#{label(rhs)} is bound to #{label(pat)}"))
    {value, Pattern.bind(pat, value, env), st}
  end

  def eval({:case, _, [subject, [do: clauses]]}, env, ctx, st) when is_list(clauses) do
    {value, env, st} = eval(subject, env, ctx, st)
    Branches.clauses(clauses, value, env, ctx, st, "case")
  end

  def eval({kind, _, [left, right]} = node, env, ctx, st) when kind in [:and, :or, :&&, :||],
    do: Branches.boolean(kind, left, right, node, env, ctx, st)

  def eval({:with, _, args} = node, env, ctx, st) when is_list(args),
    do: Branches.with_expr(args, node, env, ctx, st)

  def eval({kind, _, [condition, opts]} = node, env, ctx, st)
      when kind in [:if, :unless] and is_list(opts) do
    Branches.conditional(kind, condition, opts, node, env, ctx, st)
  end

  def eval({:%{}, _, pairs}, env, ctx, st) do
    case pairs do
      [{:|, _, [base, fields]}] when is_list(fields) ->
        {value, env, st} = eval(base, env, ctx, st)
        map_fields(fields, value, env, ctx, st)

      _ ->
        map_fields(pairs, Value.tag(:map), env, ctx, st)
    end
  end

  def eval({a, b}, env, ctx, st), do: eval({:{}, [], [a, b]}, env, ctx, st)

  def eval({:{}, _, parts}, env, ctx, st) when is_list(parts) do
    {values, env, st} = arguments(parts, env, ctx, st)
    fields = values |> Enum.with_index() |> Enum.map(fn {v, i} -> {i, v} end)
    {Value.aggregate({:tuple, length(parts)}, fields), env, st}
  end

  def eval({{:., _, [Access, :get]}, _, [obj, key]}, env, ctx, st)
      when is_binary(key) or is_atom(key) or is_number(key) do
    {value, env, st} = eval(obj, env, ctx, st)
    {Value.field(value, key), env, st}
  end

  def eval({{:., _, [obj, field]}, meta, []} = call, env, ctx, st) do
    if meta[:no_parens] && not match?({:__aliases__, _, _}, obj) do
      {v, env, st} = eval(obj, env, ctx, st)
      {Value.field(v, field), env, st}
    else
      call(call, [], env, ctx, st)
    end
  end

  def eval({:|>, _, [first, {_, _, rest} = call]}, env, ctx, st)
      when is_list(rest) or is_nil(rest),
      do: call(call, [first | rest || []], env, ctx, st)

  def eval({kind, _, parts}, env, ctx, st) when kind in [:<<>>, :<>] and is_list(parts) do
    {values, env, st} = arguments(parts, env, ctx, st)
    {if([] in values, do: [], else: Value.text(values)), env, st}
  end

  def eval({:"::", _, [expr, _]}, env, ctx, st), do: eval(expr, env, ctx, st)
  def eval({{:., _, [Kernel, :to_string]}, _, [expr]}, env, ctx, st), do: eval(expr, env, ctx, st)

  def eval({name, _, nil}, env, _ctx, st) when is_atom(name),
    do: {Pattern.read(env, name), env, st}

  def eval({kind, _, _}, env, _, st)
      when kind in [:quote, :fn, :&, :defmodule, :def, :defp, :__aliases__, :sigil_H],
      do: {Value.unknown(), env, st}

  def eval({_, _, args} = node, env, ctx, st) when is_list(args),
    do:
      if(Keyword.keyword?(List.last(args)) and Keyword.has_key?(List.last(args), :do),
        do: {Value.unknown(), env, st},
        else: call(node, args, env, ctx, st)
      )

  def eval(list, env, ctx, st) when is_list(list) do
    {values, env, st} = arguments(list, env, ctx, st)
    {if([] in values, do: [], else: Value.unknown()), env, st}
  end

  def eval(value, env, _, st) when is_atom(value) or is_binary(value) or is_number(value),
    do: {Value.literal(value), env, st}

  def eval(_, env, _, st), do: {Value.unknown(), env, st}

  defp map_fields(fields, base, env, ctx, st) do
    Enum.reduce(fields, {base, env, st}, fn
      {key, expr}, {acc, merged, state} when is_atom(key) or is_binary(key) or is_number(key) ->
        {value, next, state} = eval(expr, env, ctx, state)
        {Value.put(acc, key, value), Pattern.merge_writes(env, next, merged), state}

      {key, expr}, {_acc, merged, state} ->
        {_, next, state} = arguments([key, expr], env, ctx, state)
        {Value.unknown(), Pattern.merge_writes(env, next, merged), state}

      _, {_acc, merged, state} ->
        {Value.unknown(), merged, state}
    end)
  end

  defp arguments(args, env, ctx, st) do
    {values, result_env, st} =
      Enum.reduce_while(args, {[], env, st}, fn arg, {values, merged, acc} ->
        {v, changed, acc} = eval(arg, env, ctx, acc)
        next = {[v | values], Pattern.merge_writes(env, changed, merged), acc}
        if v == [], do: {:halt, next}, else: {:cont, next}
      end)

    {Enum.reverse(values), result_env, st}
  end

  defp call(node, args, env, ctx, st) do
    {values, env, st} = arguments(args, env, ctx, st)

    if [] in values do
      {[], env, st}
    else
      {value, st} = dispatch(node, args, values, ctx, st)
      {value, env, st}
    end
  end

  defp dispatch(node, args, values, ctx, st) do
    {module, name} = target(node, length(args), ctx)
    st = record(node, args, values, ctx, st, sink_indexes(name))
    key = {module, name, length(args)}
    target = Map.get(ctx.functions, key)

    cond do
      callable?(target, node, key, ctx, st) ->
        invoke(target, node, args, values, ctx, st)

      target == nil && LiveView.assign?(node, module, name, ctx.fun) ->
        {LiveView.assign(values, node, ctx.fun), st}

      module == [:Map] and target == nil ->
        {Value.map_call(name, values), st}

      true ->
        {Value.unknown(), st}
    end
  end

  defp target({name, _, _} = node, arity, ctx) when is_atom(name) do
    current = ctx.fun.module

    if Map.has_key?(ctx.functions, {current, name, arity}),
      do: {current, name},
      else: {Lexical.imported_module(node, {name, arity}), name}
  end

  defp target({{:., _, [{:__MODULE__, _, _}, name]}, _, _}, _, ctx), do: {ctx.fun.module, name}

  defp target({{:., _, [_module, name]}, _, _} = call, _, _),
    do: {Lexical.resolved_module(call), name}

  defp target(_, _, _), do: {nil, nil}

  defp callable?(
         %{body: {:ok, _}, guarded?: false, arity: n, params: params, visibility: vis},
         node,
         {module, _, n} = key,
         ctx,
         st
       ) do
    visible? = vis == :def or (module == ctx.fun.module and is_atom(elem(node, 0)))

    visible? and st.fuel > 0 and length(ctx.stack) < 12 and
      key not in ctx.stack and Enum.all?(params, &Pattern.supported?/1)
  end

  defp callable?(_, _, _, _, _), do: false

  defp invoke(fun, node, args, values, ctx, st) do
    sig = "#{fun.name}/#{fun.arity}"

    env =
      Enum.zip([fun.params, args, values])
      |> Enum.with_index()
      |> Enum.reduce_while(%{}, fn {{pat, arg, value}, i}, env ->
        case Enum.reject(value, &(Value.known?(&1, pat) == :no)) do
          [] ->
            {:halt, nil}

          matches ->
            caller =
              "#{ctx.fun.name}/#{ctx.fun.arity} passes #{label(arg)} as argument #{i + 1} of #{sig}"

            binding = "Argument #{i + 1} binds #{label(pat)} in #{sig}"
            # Two-element tuples and literals have no AST metadata of their own.
            param_site = if match?({_, meta, _} when is_list(meta), pat), do: pat, else: fun.head

            value =
              matches
              |> Value.step(site(ctx.fun, node, caller))
              |> Value.step(site(fun, param_site, binding))

            {:cont, Pattern.bind(pat, value, env)}
        end
      end)

    if env do
      {value, st} = helper_return(fun.return, fun, env, ctx, st)
      {Value.step(value, site(ctx.fun, node, "#{sig} returns this value")), st}
    else
      {[], st}
    end
  end

  defp helper_return({:literal, val}, _, _, _, st), do: {Value.literal(val), st}

  defp helper_return({:param, param, fields}, _, env, _, st),
    do: {Enum.reduce(fields, Pattern.read(env, param), &Value.field(&2, &1)), st}

  defp helper_return(:interpret, fun, env, ctx, st) do
    nested = %{ctx | fun: fun, stack: [{fun.module, fun.name, fun.arity} | ctx.stack]}
    {:ok, body} = fun.body

    {value, _, st} =
      Lexical.with_context(fun.scope, fn ->
        eval(body, env, nested, %{st | fuel: st.fuel - 1})
      end)

    {value, st}
  end

  # Checks resolve the owner and select the argument again when they attach
  # evidence to an actual finding. Avoid indexing every call in the project.
  defp sink_indexes(name) when name in [:query, :query!], do: [0, 1]
  defp sink_indexes(:stream), do: [0, 1]
  defp sink_indexes(:send_file), do: [2]
  defp sink_indexes(name), do: FileModule.path_indexes(name)

  defp record(_, _, _, _, st, []), do: st

  defp record(node, args, values, ctx, st, indexes) do
    flows =
      Enum.zip(args, values)
      |> Enum.with_index()
      |> Enum.filter(fn {_, i} -> i in indexes end)
      |> Enum.reduce(st.flows, fn {{arg, v}, i}, acc ->
        case Value.trails(v) do
          [] ->
            acc

          [trail | _] ->
            trail = from_source(Enum.reverse(trail), ctx.source)

            path =
              trail ++ [site(ctx.fun, node, "#{label(arg)} is used as argument #{i + 1} here")]

            put_in(
              acc,
              [Access.key(ctx.fun.file, %{}), Access.key(i, %{}), Access.key(node)],
              get_in(acc, [ctx.fun.file, i, node]) || [path]
            )
        end
      end)

    %{st | flows: flows}
  end

  defp from_source([{file, line, _, _} | _] = trail, {file, line, _, _}), do: trail
  defp from_source(trail, source), do: [source | trail]

  defp label({name, _, nil}) when is_atom(name), do: Atom.to_string(name)

  defp label({{:., _, [Access, :get]}, _, [obj, key]}) when is_binary(key),
    do: "#{label(obj)}[#{inspect(key, printable_limit: 64)}]"

  defp label({{:., _, [obj, field]}, _, []}) when is_atom(field), do: "#{label(obj)}.#{field}"
  defp label(_), do: "the expression"
end
