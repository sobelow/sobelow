defmodule Sobelow.Scan do
  @moduledoc false
  @key {__MODULE__, :table}
  @options_key {__MODULE__, :options}

  def with_scan(fun) do
    table = :ets.new(__MODULE__, [:set, :public, read_concurrency: true, write_concurrency: true])

    try do
      attach(table, fun)
    after
      :ets.delete(table)
    end
  end

  def current, do: Process.get(@key)
  def active?, do: current() != nil

  def attach(table, fun) do
    previous = current()
    previous_options = Process.get(@options_key)

    options =
      if table do
        case :ets.lookup(table, :options) do
          [{:options, options}] -> options
          [] -> nil
        end
      end

    Process.put(@key, table)
    Process.put(@options_key, options)

    try do
      fun.()
    after
      Process.put(@key, previous)
      Process.put(@options_key, previous_options)
    end
  end

  def configure(categories) do
    env = Map.new(Application.get_all_env(:sobelow))
    ignored = Enum.map(Map.get(env, :ignored, []), &Sobelow.get_mod/1)
    {_, ignored_fingerprints} = Sobelow.Fingerprint.value()

    checks =
      Map.new(categories, fn category -> {category, category.finding_modules() -- ignored} end)

    :ets.insert(current(), Enum.map(ignored_fingerprints, &{{:ignored_fingerprint, &1}, true}))

    options = %{
      env: env,
      ignored: ignored,
      checks: checks,
      root: Sobelow.Utils.normalize_path(Map.get(env, :root, ""))
    }

    :ets.insert(current(), {:options, options})
    Process.put(@options_key, options)
    :ok
  end

  def env(key) do
    case Process.get(@options_key) do
      %{env: env} -> Map.get(env, key)
      _ -> Application.get_env(:sobelow, key)
    end
  end

  def ignored(fallback) do
    case Process.get(@options_key) do
      %{ignored: ignored} -> ignored
      _ -> fallback.()
    end
  end

  def allowed_checks(category, fallback) do
    case Process.get(@options_key) do
      %{checks: checks} -> Map.get_lazy(checks, category, fallback)
      _ -> fallback.()
    end
  end

  def ignored_fingerprint?(fingerprint) do
    case Process.get(@options_key) do
      options when is_map(options) -> :ets.member(current(), {:ignored_fingerprint, fingerprint})
      _ -> Sobelow.Fingerprint.member?(fingerprint)
    end
  end

  def normalized_root do
    case Process.get(@options_key) do
      %{root: root} -> root
      _ -> Sobelow.Utils.get_root() |> Sobelow.Utils.normalize_path()
    end
  end

  def relative_filename(filename) do
    fetch({:relative_filename, filename}, fn ->
      normalized_root()
      |> (&String.replace_prefix(filename, &1, "")).()
      |> Sobelow.Utils.normalize_path()
    end)
  end

  # Preparation is bounded and ordered. The same scan cache/diagnostics are
  # attached to each worker, and source/template checks still run in phases.
  def map([], _fun), do: []
  def map([value], fun), do: [fun.(value)]

  def map(values, fun) do
    table = current()
    concurrency = System.schedulers_online()
    chunk_size = max(1, min(16, div(length(values), concurrency)))

    values
    |> Enum.chunk_every(chunk_size)
    |> Task.async_stream(fn chunk -> attach(table, fn -> Enum.map(chunk, fun) end) end,
      max_concurrency: concurrency,
      timeout: :infinity
    )
    |> Enum.flat_map(fn
      {:ok, values} -> values
      {:exit, reason} -> exit(reason)
    end)
  end

  def fetch(key, fun) do
    if table = current() do
      case :ets.lookup(table, {:cache, key}) do
        [{_, value}] ->
          count(table, :cache_hits)
          value

        [] ->
          count_miss(table, key)
          value = fun.()
          :ets.insert(table, {{:cache, key}, value})
          value
      end
    else
      fun.()
    end
  end

  def source(path), do: fetch({:source, Path.expand(path)}, fn -> File.read(path) end)

  def discover(paths, ignored?) do
    if table = current() do
      Enum.each(paths, fn path ->
        status = if ignored?.(path), do: :ignored, else: :pending
        :ets.insert_new(table, {{:file, Path.expand(path)}, status, nil})
      end)
    end

    paths
  end

  def record(path, status, message \\ nil) do
    if table = current() do
      key = {:file, Path.expand(path)}
      if :ets.member(table, key), do: :ets.insert(table, {key, status, message})
    end

    :ok
  end

  def report do
    files = if table = current(), do: :ets.match_object(table, {{:file, :_}, :_, :_}), else: []

    counts =
      Enum.reduce(files, %{scanned: 0, ignored: 0, unreadable: 0, unparseable: 0, pending: 0}, fn
        {_, status, _}, counts -> Map.update!(counts, status, &(&1 + 1))
      end)

    diagnostics =
      files
      |> Enum.flat_map(fn
        {{:file, file}, status, message} when status in [:unreadable, :unparseable] ->
          [%{file: file, status: status, message: message}]

        _ ->
          []
      end)
      |> Enum.sort_by(& &1.file)

    %{counts: Map.put(counts, :discovered, length(files)), diagnostics: diagnostics}
  end

  def print_summary(enabled?) do
    %{counts: counts, diagnostics: diagnostics} = report()

    Enum.each(diagnostics, fn
      %{status: :unparseable, message: message} ->
        IO.puts(:stderr, "WARNING: #{message}; skipping it.")

      _ ->
        :ok
    end)

    if enabled? do
      fields =
        Enum.map_join(
          [:discovered, :scanned, :ignored, :unreadable, :unparseable, :pending],
          ", ",
          fn key -> "#{key}: #{counts[key]}" end
        )

      IO.puts(:stderr, "Scan summary: " <> fields)
    end
  end

  def stats do
    if table = current() do
      table
      |> :ets.match_object({{:stat, :_, :_}, :_})
      |> Enum.reduce(%{}, fn {{:stat, key, _worker}, value}, stats ->
        Map.update(stats, key, value, &(&1 + value))
      end)
    else
      %{}
    end
  end

  defp count_miss(table, {:source, _}), do: count(table, :source_reads)
  defp count_miss(table, {:ast, _, _}), do: count(table, :ast_parses)
  defp count_miss(table, _), do: count(table, :cache_misses)
  # Per-worker counters avoid serializing every cache hit on one hot ETS key.
  defp count(table, key) do
    counter = {:stat, key, self()}
    :ets.update_counter(table, counter, {2, 1}, {counter, 0})
  end
end
