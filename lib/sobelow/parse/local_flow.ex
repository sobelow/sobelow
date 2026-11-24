defmodule Sobelow.Parse.LocalFlow do
  @moduledoc false

  alias Sobelow.Finding
  alias Sobelow.Utils

  # Only visit direct module declarations and their own definitions. A quoted
  # definition or a sibling module with the same helper name is not a caller.
  def index(ast, filename), do: modules(ast, filename, %{})

  def for_argument(meta_file, index) do
    meta_file |> Map.get(:argument_flows, %{}) |> Map.get(index, %{})
  end

  defp modules({:__block__, _, forms}, file, acc) do
    Enum.reduce(forms, acc, &modules(&1, file, &2))
  end

  defp modules({:defmodule, _, [_name, [do: body]]}, file, acc) do
    forms = statements(body)
    acc = if Utils.controller?(forms), do: module_flows(forms, file, acc), else: acc
    Enum.reduce(forms, acc, &modules(&1, file, &2))
  end

  defp modules(_, _file, acc), do: acc

  defp module_flows(forms, file, acc) do
    helpers = private_helpers(forms)

    if map_size(helpers) == 0 do
      acc
    else
      callers =
        forms
        |> Enum.flat_map(&action_calls(&1, helpers, file))
        |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))

      Enum.reduce(helpers, acc, fn {{name, _arity}, {params, body}}, flows ->
        bindings = parameter_bindings(params, name, callers, file)
        sink_flows(body, bindings, file, flows)
      end)
    end
  end

  defp private_helpers(forms) do
    clauses =
      forms |> Enum.flat_map(&private_signatures/1) |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))

    for {{name, arity} = signature, [{:defp, _, [{name, _, params}, [do: body]]}]} <- clauses,
        is_list(params) and length(params) == arity,
        Enum.all?(params, &match?({var, _, nil} when is_atom(var), &1)),
        into: %{},
        do: {signature, {params, body}}
  end

  defp parameter_bindings(params, name, callers, file) do
    arity = length(params)
    # Keep the first witness in source order for each parameter.
    for {{var, _, _} = param, i} <- Enum.with_index(params),
        [caller | _] <- [Map.get(callers, {name, arity, i}, [])],
        into: %{} do
      step =
        Finding.flow_location(file, param, "Argument #{i + 1} binds #{var} in #{name}/#{arity}")

      {var, [caller, step]}
    end
  end

  # Count guarded clauses, head-only declarations and default arities when
  # deciding whether the written call selects a unique private definition.
  defp private_signatures({:defp, _, [head | _]} = definition) do
    case unguard(head) do
      {name, _, args} when is_atom(name) and is_list(args) ->
        max = length(args)
        min = max - Enum.count(args, &match?({:\\, _, _}, &1))
        for arity <- min..max, do: {{name, arity}, definition}

      _ ->
        []
    end
  end

  defp private_signatures(_), do: []

  defp unguard({:when, _, [head | _]}), do: head
  defp unguard(head), do: head

  defp action_calls({:def, _, [head, [do: body]]}, helpers, file) do
    case unguard(head) do
      {action, _, [conn, params]} when is_atom(action) ->
        inputs = parameter_names(params)

        for {{helper, _, _} = call, args} <- direct_calls(body),
            arity = length(args),
            Map.has_key?(helpers, {helper, arity}),
            {arg, i} <- Enum.with_index(args),
            request_input?(arg, inputs, conn) do
          message =
            "#{action}/2 passes #{Macro.to_string(arg)} as argument #{i + 1} of #{helper}/#{arity}"

          {{helper, arity, i}, Finding.flow_location(file, call, message)}
        end

      _ ->
        []
    end
  end

  defp action_calls(_, _helpers, _file), do: []

  defp parameter_names({name, _, nil}) when is_atom(name), do: [name]

  defp parameter_names({:%{}, _, entries}) do
    for {key, {name, _, nil}} <- entries, is_binary(key), is_atom(name), do: name
  end

  defp parameter_names(_), do: []

  defp request_input?({{:., _, [Access, :get]}, _, [value, key]}, inputs, conn)
       when is_binary(key),
       do: request_input?(value, inputs, conn)

  defp request_input?({{:., _, [{name, _, nil}, field]}, _, []}, _, {name, _, nil})
       when field in [:params, :path_params, :query_params, :body_params], do: true

  defp request_input?({name, _, nil}, inputs, _conn) when is_atom(name), do: name in inputs
  defp request_input?(_, _, _), do: false

  defp sink_flows(_body, bindings, _file, flows) when map_size(bindings) == 0, do: flows

  defp sink_flows(body, bindings, file, flows) do
    for {call, args} <- direct_calls(body),
        {{var, _, nil}, i} <- Enum.with_index(args),
        path = Map.get(bindings, var),
        path != nil,
        reduce: flows do
      acc ->
        sink = Finding.flow_location(file, call, "#{var} is used as argument #{i + 1} here")
        flow = [path ++ [sink]]
        Map.update(acc, i, %{call => flow}, &Map.put(&1, call, flow))
    end
  end

  defp statements({:__block__, _, forms}), do: forms
  defp statements(form), do: [form]

  # Follow straight-line calls only up to the first binding or nested scope.
  # Neither side of a pipe is rewritten in the reported finding.
  defp direct_calls(body) do
    body
    |> statements()
    |> Enum.take_while(&straight_line?/1)
    |> Enum.flat_map(&call_args/1)
  end

  defp straight_line?(form) do
    {_, simple?} =
      Macro.prewalk(form, true, fn
        {kind, _, _}, _ when kind in [:=, :<-, :->, :fn, :&, :quote] -> {nil, false}
        {:do, _}, _ -> {nil, false}
        node, acc -> {node, acc}
      end)

    simple?
  end

  defp call_args({:|>, _, [value, {_, _, args} = call]}) when is_list(args) or is_nil(args),
    do: [{call, [value | args || []]}]

  defp call_args({_, _, args} = call) when is_list(args), do: [{call, args}]
  defp call_args(_), do: []
end
