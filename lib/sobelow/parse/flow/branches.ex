defmodule Sobelow.Parse.Flow.Branches do
  @moduledoc false

  alias Sobelow.Parse.Flow.{Eval, Pattern, Value}

  # Evaluate each possible arm with its own bindings. The expression returns
  # alternatives, while bindings introduced inside a clause stay inside it.
  def clauses(clauses, subject, env, ctx, st, kind) do
    {_, results, st} =
      Enum.reduce(clauses, {subject, [], st}, fn
        {:->, _, [[pattern], body]} = arm, {remaining, results, acc} ->
          {matches, rest} = split(remaining, pattern)

          if matches == [] do
            {rest, results, acc}
          else
            marker = Eval.site(ctx.fun, arm, "#{kind} selects this clause")
            vars = Pattern.bind(pattern, Value.step(matches, marker), mark_env(env, marker))
            {value, _, acc} = Eval.eval(body, vars, ctx, acc)
            {rest, [value | results], acc}
          end

        _, acc ->
          acc
      end)

    {Value.union(Enum.reverse(results)), env, st}
  end

  def conditional(kind, cond_ast, opts, node, env, ctx, st) do
    {condition, env, st} = Eval.eval(cond_ast, env, ctx, st)

    arms =
      Enum.flat_map(condition, fn shape ->
        case truth(shape) do
          :unknown -> [:do, :else]
          true -> [:do]
          false -> [:else]
        end
      end)
      |> Enum.uniq()

    {values, st} =
      Enum.map_reduce(arms, st, fn arm, acc ->
        arm = if kind == :unless, do: opposite(arm), else: arm
        marker = Eval.site(ctx.fun, node, "#{kind} selects its #{arm} branch")
        {v, _, acc} = Eval.eval(Keyword.get(opts, arm), mark_env(env, marker), ctx, acc)
        {v, acc}
      end)

    {Value.union(values), env, st}
  end

  defp opposite(:do), do: :else
  defp opposite(:else), do: :do

  defp truth(%{[] => {:literal, value}}), do: value not in [false, nil]
  defp truth(%{[] => {:tuple, _}}), do: true
  defp truth(%{[] => tag}) when tag in [:map, :socket], do: true
  defp truth(_), do: :unknown

  def boolean(kind, left, right, node, env, ctx, st) do
    {lhs, env, st} = Eval.eval(left, env, ctx, st)

    conjunction? = kind in [:and, :&&]

    {skip, evaluate?} =
      Enum.reduce(lhs, {[], false}, fn shape, {skip, evaluate?} ->
        case operand_truth(shape, kind) do
          :unknown -> {Value.union([skip, short_result(kind, shape)]), true}
          :invalid -> {skip, evaluate?}
          ^conjunction? -> {skip, true}
          _ -> {Value.union([skip, [shape]]), evaluate?}
        end
      end)

    if evaluate? do
      step = Eval.site(ctx.fun, node, "#{kind} evaluates its right operand")
      {v, _, st} = Eval.eval(right, mark_env(env, step), ctx, st)
      {Value.union([skip, v]), env, st}
    else
      {skip, env, st}
    end
  end

  defp operand_truth(%{[] => {:literal, v}}, op) when op in [:and, :or] and is_boolean(v), do: v

  defp operand_truth(shape, op) when op in [:and, :or],
    do: if(truth(shape) == :unknown, do: :unknown, else: :invalid)

  defp operand_truth(shape, _), do: truth(shape)

  defp short_result(:and, _), do: Value.literal(false)
  defp short_result(:or, _), do: Value.literal(true)
  defp short_result(:&&, _), do: Value.union([Value.literal(false), Value.literal(nil)])
  defp short_result(:||, shape), do: [shape]

  def with_expr(args, node, env, ctx, st) do
    {clauses, tail} = Enum.split(args, -1)

    case tail do
      [opts] when is_list(opts) ->
        if Keyword.keyword?(opts) and Keyword.has_key?(opts, :do) do
          with_body(clauses, opts, node, env, ctx, st)
        else
          {Value.unknown(), env, st}
        end

      _ ->
        {Value.unknown(), env, st}
    end
  end

  defp with_body(parts, opts, node, env, ctx, st) do
    {vars, failed, st} =
      Enum.reduce_while(parts, {env, [], st}, fn
        {:<-, _, [pat, expr]} = match, {vars, failed, acc} ->
          {value, vars, acc} = Eval.eval(expr, vars, ctx, acc)
          {ok, failed_here} = split(value, pat)
          fail_step = Eval.site(ctx.fun, match, "with takes the unmatched value")
          failed = Value.union([failed, Value.step(failed_here, fail_step)])
          step = Eval.site(ctx.fun, match, "with matches this pattern")

          if ok == [],
            do: {:halt, {nil, failed, acc}},
            else:
              {:cont,
               {Pattern.bind(pat, Value.step(ok, step), mark_env(vars, step)), failed, acc}}

        expr, {vars, failed, acc} ->
          {v, vars, acc} = Eval.eval(expr, vars, ctx, acc)
          if v == [], do: {:halt, {nil, failed, acc}}, else: {:cont, {vars, failed, acc}}
      end)

    {ok, _, st} = if vars, do: Eval.eval(opts[:do], vars, ctx, st), else: {[], env, st}

    {other, _, st} =
      case opts[:else] do
        arms when is_list(arms) ->
          step = Eval.site(ctx.fun, node, "with enters else")
          clauses(arms, failed, mark_env(env, step), ctx, st, "with else")

        _ ->
          {failed, env, st}
      end

    {Value.union([ok, other]), env, st}
  end

  defp mark_env(env, marker),
    do: Map.new(env, fn {k, {version, v}} -> {k, {version, Value.step(v, marker)}} end)

  defp split(values, pattern) do
    pairs = Enum.map(values, &{&1, status(&1, pattern)})

    {for({v, match} <- pairs, match != :no, do: v),
     for({v, match} <- pairs, match != :yes, do: v)}
  end

  defp status(_shape, {:when, _, [_, false]}), do: :no
  defp status(shape, {:when, _, [pat, true]}), do: Value.known?(shape, pat)

  defp status(shape, {:when, _, [pat | _]}) do
    if Value.known?(shape, pat) == :no, do: :no, else: :maybe
  end

  defp status(shape, pat), do: Value.known?(shape, pat)
end
