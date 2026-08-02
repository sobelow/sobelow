defmodule Sobelow.ScanCase do
  @moduledoc """
  Case template for end-to-end scans against the fixture applications in
  `test/fixtures/apps`.

  `Sobelow.run/0` drives the whole pipeline through named processes and
  application env, so these tests cannot run `async: true`. Each scan resets both
  before running.
  """

  use ExUnit.CaseTemplate

  alias Sobelow.FindingLog
  alias Sobelow.Fingerprint
  alias Sobelow.MetaLog

  @state_processes [FindingLog, MetaLog, Fingerprint]

  @fixture_root "test/fixtures/apps"

  # Every key `Sobelow.run/0` reads. Set them all on each scan so state cannot
  # leak between tests.
  @default_env [
    clear_skip: false,
    details: nil,
    exit_on: false,
    format: "json",
    ignored: [],
    ignored_files: [],
    mark_skip_all: false,
    out: nil,
    private: true,
    router: nil,
    skip: false,
    strict: false,
    threshold: :low,
    verbose: false,
    version: false
  ]

  using do
    quote do
      import Sobelow.ScanCase
    end
  end

  setup do
    # A scan writes a dozen keys into the global :sobelow env. Restore whatever
    # was there so other tests, which may rely on ambient env, are unaffected by
    # the options a scan happened to run with.
    original_env = Application.get_all_env(:sobelow)

    on_exit(fn ->
      stop_state_processes()
      restore_env(original_env)
    end)

    :ok
  end

  @doc """
  Scans a fixture app and returns the decoded JSON report.

  Options are merged over the defaults and written to the `:sobelow`
  application env, using the same keys `Mix.Tasks.Sobelow` sets.
  """
  def scan(fixture, opts \\ []) do
    {stdout, _stderr} = scan_io(fixture, opts)
    Jason.decode!(stdout)
  end

  @doc """
  Scans a fixture app and returns the raw `{stdout, stderr}` it produced.
  """
  def scan_io(fixture, opts \\ []) do
    prepare_env(fixture, opts)

    stderr =
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        stdout = ExUnit.CaptureIO.capture_io(fn -> Sobelow.run() end)
        send(self(), {:stdout, stdout})
      end)

    receive do
      {:stdout, stdout} -> {stdout, stderr}
    after
      0 -> {"", stderr}
    end
  end

  @doc """
  Absolute-free path to a fixture app, relative to the project root.
  """
  def fixture_path(fixture), do: Path.join(@fixture_root, fixture)

  @doc """
  All findings in a report, flattened across confidence levels, each tagged with
  its confidence.
  """
  def findings(report) do
    Enum.flat_map([:high, :medium, :low], fn confidence ->
      report
      |> get_in(["findings", "#{confidence}_confidence"])
      |> List.wrap()
      |> Enum.map(&Map.put(&1, "confidence", to_string(confidence)))
    end)
  end

  @doc """
  Sorted, deduplicated finding type prefixes (e.g. `"Config.Secrets"`).
  """
  def finding_modules(report) do
    report
    |> findings()
    |> Enum.map(&(&1 |> Map.fetch!("type") |> String.split(":") |> hd()))
    |> Enum.uniq()
    |> Enum.sort()
  end

  @doc """
  Findings whose type starts with the given module prefix.
  """
  def findings_for(report, module) do
    report
    |> findings()
    |> Enum.filter(&String.starts_with?(Map.fetch!(&1, "type"), module <> ":"))
  end

  @doc """
  Writes a file into a fixture app for the duration of the test.

  Used for fixtures that must not be committed in a broken state, because
  `mix format --check-formatted` covers `test/**`.

  If the path is an existing, committed fixture, its original contents are
  restored afterwards rather than deleted, so a test can vary a checked-in
  fixture without destroying it.
  """
  def temp_fixture_file(fixture, relative_path, contents) do
    path = Path.join(fixture_path(fixture), relative_path)
    original = File.read(path)

    File.mkdir_p!(Path.dirname(path))
    File.write!(path, contents)

    ExUnit.Callbacks.on_exit(fn ->
      case original do
        {:ok, original} -> File.write!(path, original)
        {:error, _} -> File.rm_rf!(path)
      end
    end)

    path
  end

  defp prepare_env(fixture, opts) do
    stop_state_processes()

    @default_env
    |> Keyword.merge(opts)
    |> Keyword.put(:root, fixture_path(fixture))
    |> Enum.each(fn {key, value} -> Application.put_env(:sobelow, key, value) end)
  end

  # These are named, so a previous scan's process would silently be reused with
  # its accumulated findings. Stopping normally avoids killing the linked test
  # process.
  defp stop_state_processes do
    Enum.each(@state_processes, fn mod ->
      case Process.whereis(mod) do
        nil -> :ok
        pid -> safe_stop(pid)
      end
    end)
  end

  defp safe_stop(pid) do
    GenServer.stop(pid, :normal, 1_000)
  catch
    :exit, _ -> :ok
  end

  defp restore_env(original_env) do
    Enum.each(Application.get_all_env(:sobelow), fn {key, _} ->
      Application.delete_env(:sobelow, key)
    end)

    Enum.each(original_env, fn {key, value} ->
      Application.put_env(:sobelow, key, value)
    end)
  end
end
