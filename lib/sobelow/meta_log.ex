defmodule Sobelow.MetaLog do
  @moduledoc false

  use GenServer
  alias Sobelow.Parse

  def start_link do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def add_templates(templates) do
    GenServer.cast(__MODULE__, {:add, templates})
  end

  def get_templates do
    GenServer.call(__MODULE__, :get_templates)
  end

  def get_templates(paths) do
    GenServer.call(__MODULE__, {:get_templates, paths})
  end

  def delete_raw(var, template_path) do
    GenServer.cast(__MODULE__, {:delete_raw, {var, template_path}})
  end

  def init(:ok) do
    {:ok, %{:templates => %{}}}
  end

  def handle_cast({:add, templates}, log) do
    {:noreply, Map.put(log, :templates, templates)}
  end

  def handle_cast({:delete_raw, {var, template_path}}, log) do
    raw_funs =
      get_in(log, [:templates, template_path, :raw])
      |> Enum.reject(fn raw ->
        Enum.member?(Parse.get_template_vars([raw]), var)
      end)

    {:noreply, put_in(log, [:templates, template_path, :raw], raw_funs)}
  end

  def handle_call(:get_templates, _from, log) do
    {:reply, log.templates, log}
  end

  def handle_call({:get_templates, paths}, _from, log) do
    {:reply, Map.take(log.templates, paths), log}
  end
end
