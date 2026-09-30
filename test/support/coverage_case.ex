defmodule Sobelow.CoverageCase do
  @moduledoc false
  use ExUnit.CaseTemplate

  @processes [Sobelow.FindingLog, Sobelow.Fingerprint, Sobelow.MetaLog]

  using do
    quote do
      import ExUnit.CaptureIO
      import Sobelow.CoverageCase
      alias Sobelow.{Finding, FindingLog, Parse, Print}
    end
  end

  setup do
    original = Application.get_all_env(:sobelow)
    clear_env()

    for {key, value} <- [
          root: ".",
          app_name: "basic",
          format: "json",
          threshold: :low,
          skip: false,
          strict: false,
          verbose: false,
          ignored: [],
          ignored_files: [],
          private: true
        ],
        do: Application.put_env(:sobelow, key, value)

    reset_logs()

    ExUnit.Callbacks.on_exit(fn ->
      stop_logs()
      clear_env()
      for {key, value} <- original, do: Application.put_env(:sobelow, key, value)
    end)

    :ok
  end

  def quoted(source), do: Code.string_to_quoted!(source, columns: true)

  def logged_findings do
    Sobelow.FindingLog.log()
    |> Map.values()
    |> List.flatten()
    |> Enum.map(&elem(&1, 1))
  end

  def reset_logs do
    stop_logs()
    for module <- @processes, do: module.start_link()
    :ok
  end

  defp stop_logs do
    for module <- @processes, pid = Process.whereis(module), do: safe_stop(pid)
  end

  defp safe_stop(pid) do
    GenServer.stop(pid)
  catch
    :exit, _ -> :ok
  end

  defp clear_env do
    for {key, _} <- Application.get_all_env(:sobelow), do: Application.delete_env(:sobelow, key)
  end
end
