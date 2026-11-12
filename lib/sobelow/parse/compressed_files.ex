defmodule Sobelow.Parse.CompressedFiles do
  @moduledoc false

  alias Sobelow.Parse

  @scopes [:fn, :quote, :&, :case, :if, :unless, :cond, :with, :for, :receive, :try]

  def findings({_, _, [_head, [do: body]]} = fun) do
    opens =
      for {module, name, arities, kind} <- [
            {[:File], :open, [2, 3], :tuple},
            {[:File], :open!, [2, 3], :device},
            {:file, :open, [2], :tuple}
          ],
          {call, _, args} <- Parse.calls_with_args(fun, [{module, name, arities}]),
          into: %{},
          do: {call, {kind, args}}

    reads = call_map(fun, [{[:IO], :read, [2]}, {[:IO], :binread, [2]}])
    closes = call_map(fun, [{[:File], :close, [1]}, {:file, :close, [1]}])
    context = %{opens: opens, reads: reads, closes: closes}
    {_, findings} = walk(body, %{}, [], context)
    Enum.reverse(findings)
  end

  def findings(_), do: []

  defp call_map(fun, specs) do
    Map.new(Parse.calls_with_args(fun, specs), fn {call, _, args} -> {call, args} end)
  end

  defp walk({:__block__, _, statements}, devices, found, context),
    do: walk_list(statements, devices, found, context)

  defp walk({:|>, _, [_, call]}, devices, found, context) do
    walk(call, devices, found, context)
  end

  defp walk({:=, _, [pattern, value]}, devices, found, context) do
    {devices, found} = walk(value, devices, found, context)
    devices = Map.drop(devices, variables(pattern))

    devices =
      case Map.get(context.opens, call_node(value)) do
        {kind, [path, modes]} ->
          case {binding(pattern, kind), input_variables(path, modes)} do
            {nil, _} -> devices
            {_, []} -> devices
            {name, vars} -> Map.put(devices, name, vars)
          end

        _ ->
          devices
      end

    {devices, found}
  end

  defp walk({scope, _, _}, _devices, found, _) when scope in @scopes,
    do: {%{}, found}

  defp walk(node, devices, found, context) when is_tuple(node) do
    cond do
      Map.has_key?(context.reads, node) ->
        [device, amount] = Map.fetch!(context.reads, node)
        vars = Map.get(devices, variable(device), [])
        found = if amount in [:all, :eof] and vars != [], do: [{node, vars} | found], else: found
        {devices, found}

      Map.has_key?(context.closes, node) ->
        [device] = Map.fetch!(context.closes, node)
        {Map.delete(devices, variable(device)), found}

      Map.has_key?(context.opens, node) ->
        callback(node, devices, found, context)

      true ->
        # Unknown calls may close, transfer or otherwise alter a handle. Do not
        # retain it across escape, branches or nested scopes. No alias inference.
        {devices, found} = walk_list(Tuple.to_list(node), devices, found, context)
        {Map.drop(devices, variables(node)), found}
    end
  end

  defp walk(list, devices, found, context) when is_list(list),
    do: walk_list(list, devices, found, context)

  defp walk(_, devices, found, _), do: {devices, found}

  defp walk_list(nodes, devices, found, context) do
    Enum.reduce(nodes, {devices, found}, fn node, {devices, found} ->
      walk(node, devices, found, context)
    end)
  end

  defp callback(node, devices, found, context) do
    {kind, args} = Map.fetch!(context.opens, node)

    # An open's arguments or callback may capture, close or transfer an outer
    # handle, even when its modes/callback are outside the supported analysis.
    devices = Map.drop(devices, variables(args))

    case {kind, args} do
      {_, [path, modes, {:fn, _, [{:->, _, [[parameter], body]}]}]} ->
        case {variable(parameter), input_variables(path, modes)} do
          {nil, _} ->
            {devices, found}

          {_, []} ->
            {devices, found}

          {name, vars} ->
            {_, found} = walk(body, %{name => vars}, found, context)
            {devices, found}
        end

      _ ->
        {devices, found}
    end
  end

  defp call_node({:|>, _, [_, call]}), do: call
  defp call_node(node), do: node

  defp input_variables(path, modes) when is_list(modes) do
    if Enum.all?(modes, &Macro.quoted_literal?/1) and
         Enum.any?([:compressed, :compressed_one], &(&1 in modes)) and
         not Enum.any?([:write, :append, :raw, :ram], &(&1 in modes)),
       do: Parse.binary_input_vars(path),
       else: []
  end

  defp input_variables(_, _), do: []

  defp binding({:ok, device}, :tuple), do: variable(device)
  defp binding(device, :device), do: variable(device)
  defp binding(_, _), do: nil

  defp variable({name, _, context}) when is_atom(name) and is_atom(context) and name != :_,
    do: name

  defp variable(_), do: nil

  defp variables(ast) do
    {_, names} =
      Macro.prewalk(ast, [], fn node, names ->
        case variable(node) do
          nil -> {node, names}
          name -> {node, [name | names]}
        end
      end)

    names
  end
end
