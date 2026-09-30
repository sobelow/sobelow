defmodule Sobelow.Benchmark do
  @moduledoc false
  @profiles ~w(mixed config phoenix pipelines large-functions small-files heex)
  @formats ~w(quiet json sarif)

  def run(args) do
    {:ok, _} = Application.ensure_all_started(:ex_unit)

    {opts, rest, invalid} =
      OptionParser.parse(args,
        strict: [
          profile: :string,
          format: :string,
          files: :integer,
          endpoints: :integer,
          runs: :integer,
          reference: :string,
          save_reference: :string,
          out: :string,
          memory: :boolean
        ]
      )

    if rest != [] or invalid != [], do: raise("invalid benchmark arguments")
    profiles = select(Keyword.get(opts, :profile, "mixed"), @profiles)
    formats = select(Keyword.get(opts, :format, "quiet"), @formats)
    runs = Keyword.get(opts, :runs, 5)
    if runs < 1, do: raise("runs must be positive")
    reference = if opts[:reference], do: opts[:reference] |> File.read!() |> Jason.decode!()
    runtime = %{"elixir" => System.version(), "otp" => System.otp_release()}
    if reference && reference["runtime"] != runtime, do: raise("reference runtime differs")

    results =
      for profile <- profiles, format <- formats do
        root =
          Path.join(
            System.tmp_dir!(),
            "sobelow-bench-#{System.pid()}-#{System.unique_integer([:positive])}"
          )

        try do
          dimensions = fixture(root, profile, opts)
          # Warm loading separately; measured scans always start with fresh state/cache.
          scan(root, format)
          measurements = for _ <- 1..runs, do: measure(root, format)
          signatures = Enum.map(measurements, & &1.signature) |> Enum.uniq()

          if length(signatures) != 1,
            do: raise("nondeterministic findings/output: #{profile}/#{format}")

          signature = hd(signatures)
          key = profile <> "/" <> format

          if reference && reference["contracts"][key] != signature,
            do: raise("findings/output changed: #{key}")

          times = Enum.map(measurements, & &1.ms) |> Enum.sort()
          memory = if opts[:memory], do: measure_memory(root, format), else: nil

          %{
            key: key,
            dimensions: dimensions,
            signature: signature,
            median_ms: Enum.at(times, div(runs, 2)),
            min_ms: hd(times),
            max_ms: List.last(times),
            median_reductions:
              measurements |> Enum.map(& &1.reductions) |> Enum.sort() |> Enum.at(div(runs, 2)),
            sampled_memory: memory
          }
        after
          stop_state()
          File.rm_rf!(root)
        end
      end

    report = %{
      runtime: runtime,
      runs: runs,
      results: results,
      system: %{
        schedulers: System.schedulers_online(),
        architecture: to_string(:erlang.system_info(:system_architecture))
      }
    }

    if opts[:save_reference] do
      contracts = Map.new(results, &{&1.key, &1.signature})

      File.write!(
        opts[:save_reference],
        Jason.encode!(%{runtime: runtime, contracts: contracts}, pretty: true)
      )
    end

    encoded = Jason.encode!(report, pretty: true)
    if opts[:out], do: File.write!(opts[:out], encoded), else: IO.puts(encoded)
  end

  defp select("all", choices), do: choices

  defp select(choice, choices) do
    if choice not in choices, do: raise("unknown selection: #{choice}")
    [choice]
  end

  defp measure(root, format) do
    stop_state()
    {before, _} = :erlang.statistics(:reductions)
    {elapsed, output} = :timer.tc(fn -> scan(root, format) end)
    {after_scan, _} = :erlang.statistics(:reductions)

    %{
      ms: elapsed / 1000,
      reductions: after_scan - before,
      signature: signature(root, output, format)
    }
  end

  defp scan(root, format) do
    stop_state()

    ExUnit.CaptureIO.capture_io(:stderr, fn ->
      output =
        ExUnit.CaptureIO.capture_io(fn ->
          Mix.Tasks.Sobelow.run(["--private", "--root", root, "--no-router", "--format", format])
        end)

      send(self(), {:benchmark_output, output})
    end)

    receive do
      {:benchmark_output, output} -> output
    end
  end

  defp signature(root, output, format) do
    findings = Sobelow.FindingLog.log() |> Map.values() |> List.flatten()

    contracts =
      Enum.map(findings, fn {_details, finding, _} ->
        finding |> Map.from_struct() |> Map.update!(:filename, &normalize(&1, root))
      end)
      |> Enum.sort()

    rendered = if format in ["json", "sarif"], do: Jason.decode!(output), else: output

    %{
      "findings" => length(findings),
      "contracts_sha256" => contracts |> canonical() |> digest(),
      "output_sha256" => rendered |> normalize(root) |> canonical() |> digest()
    }
  end

  defp digest(term),
    do: :crypto.hash(:sha256, :erlang.term_to_binary(term)) |> Base.encode16(case: :lower)

  defp canonical(map) when is_map(map),
    do: map |> Enum.map(fn {k, v} -> {k, canonical(v)} end) |> Enum.sort()

  defp canonical(list) when is_list(list), do: Enum.map(list, &canonical/1)

  defp canonical(tuple) when is_tuple(tuple),
    do: tuple |> Tuple.to_list() |> Enum.map(&canonical/1) |> List.to_tuple()

  defp canonical(term), do: term

  defp normalize(map, root) when is_map(map),
    do: Map.new(map, fn {k, v} -> {k, normalize(v, root)} end)

  defp normalize(list, root) when is_list(list), do: Enum.map(list, &normalize(&1, root))

  defp normalize(string, root) when is_binary(string) do
    string
    |> String.replace(root <> "/", "")
    |> String.replace(String.trim_leading(root, "/") <> "/", "")
  end

  defp normalize(term, _root), do: term

  defp measure_memory(root, format) do
    stop_state()
    :erlang.garbage_collect()
    baseline = :erlang.memory(:total)
    owner = self()
    sampler = spawn_link(fn -> sample_memory(owner, baseline) end)
    scan(root, format)
    send(sampler, :stop)

    receive do
      {:peak_memory, peak} ->
        %{
          baseline_vm_bytes: baseline,
          peak_vm_bytes: peak,
          increase_bytes: max(0, peak - baseline),
          interval_ms: 5
        }
    end
  end

  defp sample_memory(owner, peak) do
    peak = max(peak, :erlang.memory(:total))

    receive do
      :stop -> send(owner, {:peak_memory, max(peak, :erlang.memory(:total))})
    after
      5 -> sample_memory(owner, peak)
    end
  end

  defp stop_state do
    for module <- [Sobelow.FindingLog, Sobelow.Fingerprint, Sobelow.MetaLog] do
      if pid = Process.whereis(module), do: GenServer.stop(pid, :normal)
    end
  end

  defp fixture(root, profile, opts) do
    write(
      root,
      "mix.exs",
      "defmodule Bench.MixProject do\n def project, do: [app: :bench]\nend\n"
    )

    {files, functions, endpoints} =
      case profile do
        "mixed" -> {Keyword.get(opts, :files, 200), 10, Keyword.get(opts, :endpoints, 400)}
        "config" -> {20, 10, 4000}
        "small-files" -> {1000, 2, 20}
        "large-functions" -> {10, 2, 20}
        "pipelines" -> {40, 10, 20}
        "phoenix" -> {24, 5, 20}
        "heex" -> {1, 1, 20}
      end

    if files < 1 or endpoints < 1, do: raise("fixture dimensions must be positive")

    for index <- 1..files do
      if profile in ["phoenix", "heex"] do
        controller(root, index, functions, if(profile == "heex", do: 4000, else: 40))
      else
        functions = Enum.map_join(1..functions, "\n", &function(profile, &1))

        write(
          root,
          "lib/module#{index}.ex",
          "defmodule Bench.Module#{index} do\n#{functions}\nend\n"
        )
      end
    end

    settings =
      Enum.map_join(1..endpoints, "\n", fn index ->
        "config :bench, Bench.Web#{index}.Endpoint, https: [port: 443], force_ssl: true"
      end)

    write(root, "config/prod.exs", settings)

    %{
      source_files: files,
      functions_per_file: functions,
      endpoint_settings: endpoints,
      template_interpolations:
        if(profile == "heex", do: 4000, else: if(profile == "phoenix", do: files * 40, else: 0))
    }
  end

  defp function("pipelines", index) do
    pipeline = Enum.map_join(1..20, "\n", fn _ -> "|> String.trim()" end)
    "def read#{index}(path), do: path\n#{pipeline}\n|> File.read()"
  end

  defp function("large-functions", index) do
    statements =
      Enum.map_join(1..100, "\n", fn n ->
        "local#{n} = path\nFile.read(local#{n})\nif path != nil, do: String.to_atom(path)"
      end)

    "def read#{index}(path) do\n#{statements}\nend"
  end

  defp function(_profile, index), do: "def read#{index}(path), do: File.read(path)"

  defp controller(root, index, functions, interpolations) do
    functions =
      Enum.map_join(1..functions, "\n", fn n ->
        "def action#{n}(conn, params) do\n local = params\nFile.read(local[\"path\"])\nrender(conn, \"index.html\", name: params[\"name\"])\nend"
      end)

    write(root, "lib/bench_web/controllers/page#{index}_controller.ex", """
    defmodule Bench.Page#{index}Controller do
      use Bench.Web, :controller
      alias Plug.Conn, as: Connection
      import Phoenix.Controller
      #{functions}
      def response(conn, input), do: conn |> Connection.put_resp_content_type("text/html") |> Connection.send_resp(200, input)
      def inline(assigns), do: ~H"<section>{raw(@name)}</section>"
    end
    """)

    expressions =
      Enum.map_join(1..interpolations, "\n", fn n ->
        if rem(n, 2) == 0,
          do: "<span title={raw(@description)}>value</span>",
          else: "<span>{raw(@description)}</span>"
      end)

    write(root, "lib/bench_web/controllers/page#{index}_html/index.html.heex", """
    <%!-- {raw(@comment)} --%>
    <script>{raw(@script)}</script>
    <div phx-no-curly-interpolation>{raw(@disabled)}</div>
    <h1>{raw(@name)}</h1>
    <%= Phoenix.HTML.raw(@legacy) %>
    #{expressions}
    """)
  end

  defp write(root, relative, contents) do
    path = Path.join(root, relative)
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, contents)
  end
end
