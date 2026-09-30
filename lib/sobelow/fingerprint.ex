defmodule Sobelow.Fingerprint do
  @moduledoc false

  use Agent
  @batch_key {__MODULE__, :batch}

  def start_link do
    Agent.start_link(fn -> {MapSet.new(), MapSet.new()} end, name: __MODULE__)
  end

  def value do
    Agent.get(__MODULE__, & &1)
  end

  def new_skips do
    Agent.get(__MODULE__, fn {total_set, ignore_set} ->
      MapSet.difference(total_set, ignore_set) |> MapSet.to_list()
    end)
  end

  def with_batch(fun) do
    if Process.get(@batch_key) do
      fun.()
    else
      Process.put(@batch_key, MapSet.new())

      try do
        fun.()
      after
        fingerprints = Process.delete(@batch_key)
        if MapSet.size(fingerprints) > 0, do: put_many(fingerprints)
      end
    end
  end

  def put(fingerprint) do
    if batch = Process.get(@batch_key) do
      Process.put(@batch_key, MapSet.put(batch, fingerprint))
      :ok
    else
      put_many(MapSet.new([fingerprint]))
    end
  end

  defp put_many(fingerprints) do
    Agent.update(__MODULE__, fn {total_set, ignore_set} ->
      {MapSet.union(total_set, fingerprints), ignore_set}
    end)
  end

  def put_ignore(fingerprint) do
    Agent.update(__MODULE__, fn {total_set, ignore_set} ->
      {total_set, MapSet.put(ignore_set, fingerprint)}
    end)
  end

  def member?(fingerprint) do
    Agent.get(__MODULE__, fn {_, ignore_set} -> MapSet.member?(ignore_set, fingerprint) end)
  end
end
