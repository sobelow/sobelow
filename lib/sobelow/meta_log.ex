defmodule Sobelow.MetaLog do
  @moduledoc false

  use GenServer

  def start_link do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def add_templates(templates) do
    GenServer.call(__MODULE__, {:add, templates}, :infinity)
  end

  def get_templates do
    GenServer.call(__MODULE__, :get_templates)
  end

  def get_templates(paths) do
    GenServer.call(__MODULE__, {:get_templates, paths})
  end

  def init(:ok) do
    {:ok, %{:templates => %{}}}
  end

  def handle_call({:add, templates}, _from, log) do
    {:reply, :ok, Map.put(log, :templates, templates)}
  end

  def handle_call(:get_templates, _from, log) do
    {:reply, log.templates, log}
  end

  def handle_call({:get_templates, paths}, _from, log) do
    {:reply, Map.take(log.templates, paths), log}
  end
end
