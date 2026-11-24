defmodule Sobelow.Parse.Flow.Value do
  @moduledoc false

  # An alternative stores a shape tag at [] and individual fields at key paths.
  # Flat paths bound copying on code such as x = {x, x}. Keep branch alternatives
  # separate so a tag from one tuple cannot select the payload of another.
  @variants 8
  @fields 128
  @depth 12
  def unknown, do: tag(:unknown)
  def input, do: [%{[] => {:input, []}}]
  def literal(value), do: [%{[] => {:literal, value}}]
  def tag(shape), do: [%{[] => shape}]

  def union(values), do: values |> Enum.concat() |> Enum.uniq() |> Enum.take(@variants)

  def aggregate(tag, entries) do
    Enum.reduce(entries, tag(tag), fn {key, value}, acc -> put(acc, key, value) end)
  end

  def put(values, key, replacements) do
    for container <- values, replacement <- replacements do
      base =
        for {path, entry} <- container, not match?([^key | _], path), into: %{}, do: {path, entry}

      if map_size(base) + map_size(replacement) > @fields do
        %{[] => :unknown}
      else
        Enum.reduce(replacement, base, fn {path, entry}, fields ->
          if length(path) < @depth, do: Map.put(fields, [key | path], entry), else: fields
        end)
      end
    end
    |> Enum.uniq()
    |> Enum.take(@variants)
  end

  def field(values, key) do
    Enum.map(values, fn shape ->
      fields = for {[^key | rest], v} <- shape, into: %{}, do: {rest, v}

      case {map_size(fields), Map.get(shape, [])} do
        {0, {:input, _} = origin} -> %{[] => origin}
        {0, _} -> %{[] => :unknown}
        _ -> fields
      end
    end)
    |> Enum.uniq()
  end

  def step(values, location) do
    Enum.map(values, fn shape ->
      Map.new(shape, fn
        {key, {:input, trail}} when length(trail) < 48 -> {key, {:input, [location | trail]}}
        {key, {:input, _}} -> {key, :unknown}
        entry -> entry
      end)
    end)
  end

  def trails(values), do: for(%{[] => {:input, trail}} <- values, do: trail)

  def map_call(:put, [map, [%{[] => {:literal, key}}], value]),
    do: put(Enum.filter(map, &possible_map?/1), key, value)

  def map_call(:get, [map, key]), do: map_call(:get, [map, key, literal(nil)])

  def map_call(:get, [map, [%{[] => {:literal, key}}], default]) do
    for shape <- map, possible_map?(shape) do
      case {Map.has_key?(shape, [key]), Map.get(shape, [])} do
        {true, _} -> field([shape], key)
        {false, :map} -> default
        _ -> union([field([shape], key), default])
      end
    end
    |> union()
  end

  def map_call(:fetch, [map, [%{[] => {:literal, key}}]]) do
    for shape <- map, possible_map?(shape) do
      ok = aggregate({:tuple, 2}, [{0, literal(:ok)}, {1, field([shape], key)}])

      cond do
        Map.has_key?(shape, [key]) -> ok
        Map.get(shape, []) == :map -> literal(:error)
        true -> union([ok, literal(:error)])
      end
    end
    |> union()
  end

  def map_call(_, _), do: unknown()

  defp possible_map?(%{[] => {:input, _}}), do: true
  defp possible_map?(shape), do: Map.get(shape, []) in [:map, :socket, :unknown]

  def text(values) do
    case Enum.flat_map(values, &trails/1) do
      [] -> unknown()
      trails -> for trail <- Enum.take(Enum.uniq(trails), @variants), do: %{[] => {:input, trail}}
    end
  end

  def known?(shape, pattern) when is_atom(pattern) or is_number(pattern) or is_binary(pattern) do
    case Map.get(shape, []) do
      {:literal, value} -> if value === pattern, do: :yes, else: :no
      tag when tag in [nil, :unknown] -> :maybe
      {:input, _} -> :maybe
      _ -> :no
    end
  end

  def known?(_, {name, _, nil}) when is_atom(name), do: :yes

  def known?(shape, {:=, _, [left, right]}) do
    case {known?(shape, left), known?(shape, right)} do
      {:yes, :yes} -> :yes
      {:no, _} -> :no
      {_, :no} -> :no
      _ -> :maybe
    end
  end

  def known?(shape, {a, b}), do: known?(shape, {:{}, [], [a, b]})

  def known?(shape, {:{}, _, parts}) when is_list(parts) do
    match_fields(
      shape,
      {:tuple, length(parts)},
      parts |> Enum.with_index() |> Enum.map(fn {p, i} -> {i, p} end)
    )
  end

  def known?(shape, {:%{}, _, entries}) do
    if Enum.all?(entries, &literal_entry?/1), do: match_fields(shape, :map, entries), else: :maybe
  end

  def known?(_, _), do: :maybe

  def literal_entry?({key, _}), do: is_atom(key) or is_binary(key) or is_number(key)
  def literal_entry?(_), do: false

  defp match_fields(shape, tag, entries) do
    case Map.get(shape, []) do
      ^tag ->
        results =
          Enum.map(entries, fn {key, pattern} ->
            [sub] = field([shape], key)

            if Map.has_key?(shape, [key]), do: known?(sub, pattern), else: :no
          end)

        cond do
          :no in results -> :no
          :maybe in results -> :maybe
          true -> :yes
        end

      {:literal, _} ->
        :no

      {:tuple, _} ->
        :no

      :map ->
        :no

      _ ->
        :maybe
    end
  end
end
