defmodule Sobelow.Parse.Flow.LiveView do
  @moduledoc false

  alias Sobelow.{Finding, Lexical, Utils}
  alias Sobelow.Parse.Flow.Value

  def module?(forms),
    do:
      Utils.has_use_type?(forms, :live_view) or
        Enum.any?(forms, &match?({:use, _, [{:__aliases__, _, [:Phoenix, :LiveView]} | _]}, &1))

  def assign?({:assign, _, _} = call, _, :assign, %{kind: :live_view}),
    do: Lexical.live_assign?(call)

  def assign?({{:., _, _}, _, _}, module, :assign, _),
    do: module in [[:Phoenix, :Component], [:Phoenix, :LiveView]]

  def assign?(_, _, _, _), do: false

  def assign([socket, [%{[] => {:literal, key}}], value], node, fun) when is_atom(key) do
    sockets = Enum.filter(socket, &(Map.get(&1, []) == :socket))
    step = Finding.flow_location(fun.file, node, "assign stores the event value in @#{key}")

    Enum.flat_map(sockets, fn shape ->
      assigns = [shape] |> Value.field(:assigns) |> Value.put(key, Value.step(value, step))
      Value.put([shape], :assigns, assigns)
    end)
  end

  def assign(_, _, _), do: Value.unknown()

  def returned(%{kind: :live_view, name: :handle_event} = fun, results, sockets) do
    assigns =
      for shape <- results,
          %{[] => {:literal, tag}} <- Value.field([shape], 0),
          i = socket_position(tag, Map.get(shape, [])),
          i != nil,
          %{[] => :socket} = sock <- Value.field([shape], i),
          fields <- Value.field([sock], :assigns),
          do: fields

    Map.update(sockets, {fun.file, fun.module}, assigns, &Enum.uniq(&1 ++ assigns))
  end

  def returned(_, _, sockets), do: sockets

  defp socket_position(:noreply, {:tuple, 2}), do: 1
  defp socket_position(:reply, {:tuple, 3}), do: 2
  defp socket_position(_, _), do: nil

  def templates(defs, sockets, templates) do
    views = Enum.group_by(defs, &{&1.file, &1.module})

    Enum.reduce(sockets, {%{}, templates}, fn {{file, module} = key, assigns},
                                              {inline, external} ->
      renders = Enum.filter(views[key], &(&1.name == :render and &1.arity == 1))
      template = Path.rootname(file) <> ".html.heex"

      case renders do
        [%{visibility: :def, guarded?: false, body: {:ok, {:sigil_H, _, _}}, definition_key: id}] ->
          {Map.update(inline, file, %{id => assigns}, &Map.put(&1, id, assigns)), external}

        [] ->
          case external do
            %{^template => meta} ->
              if List.last(module) |> Atom.to_string() |> Macro.underscore() ==
                   Path.basename(file, ".ex") do
                {inline,
                 Map.put(
                   external,
                   template,
                   Map.put(meta, :live_assigns, assigns)
                 )}
              else
                {inline, external}
              end

            _ ->
              {inline, external}
          end

        _ ->
          {inline, external}
      end
    end)
  end

  def raw_flows(_calls, [], _file), do: %{}

  def raw_flows(calls, assigns, file) do
    for expression <- calls,
        {call, arg} <- raw_argument(expression),
        [key | _] = fields <- [assign_fields(arg)],
        is_atom(key),
        [trail | _] <- [Enum.reduce(fields, assigns, &Value.field(&2, &1)) |> Value.trails()],
        into: %{} do
      sink = Finding.flow_location(file, call, "raw outputs the @#{key} assign")
      {call, [Enum.reverse(trail, [sink])]}
    end
  end

  defp raw_argument({:|>, _, [arg, {_, _, args} = call]}) when args in [[], nil],
    do: [{call, arg}]

  defp raw_argument({_, _, [arg]} = call), do: [{call, arg}]
  defp raw_argument(_), do: []

  defp assign_fields(
         {{:., _, [_engine, :fetch_assign!]}, _, [{:var!, _, [{:assigns, _, EEx.Engine}]}, key]}
       )
       when is_atom(key), do: [key]

  defp assign_fields({{:., _, [obj, key]}, _, []}) when is_atom(key), do: append_key(obj, key)

  defp assign_fields({{:., _, [Access, :get]}, _, [obj, key]})
       when is_binary(key) or is_atom(key), do: append_key(obj, key)

  defp assign_fields(_), do: []

  defp append_key(obj, key) do
    case assign_fields(obj) do
      [] -> []
      path -> path ++ [key]
    end
  end
end
