defmodule Sobelow.FindingLog do
  @moduledoc false

  use GenServer

  def start_link do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @batch_key {__MODULE__, :batch}

  def with_batch(fun) do
    if Process.get(@batch_key) do
      fun.()
    else
      Process.put(@batch_key, %{entries: [], sources: %{}})

      try do
        fun.()
      after
        batch = Process.delete(@batch_key)
        if batch.entries != [], do: GenServer.cast(__MODULE__, {:add_batch, batch})
      end
    end
  end

  def add({details, finding, metadata}, severity) do
    batch = Process.get(@batch_key) || %{entries: [], sources: %{}}
    source = finding.fun_source

    reference =
      if source != nil do
        Sobelow.FunctionAnalysis.fetch(source, :finding_source, &make_ref/0)
      end

    entry = {details, %{finding | fun_source: nil}, metadata, reference}

    batch = %{
      batch
      | entries: [{severity, entry} | batch.entries],
        sources:
          if(reference, do: Map.put_new(batch.sources, reference, source), else: batch.sources)
    }

    if Process.get(@batch_key) do
      Process.put(@batch_key, batch)
    else
      GenServer.cast(__MODULE__, {:add_batch, batch})
    end

    :ok
  end

  def log, do: read_log(true)
  def counts, do: GenServer.call(__MODULE__, :counts)

  defp read_log(sources?) do
    {findings, sources} = GenServer.call(__MODULE__, {:log, sources?})

    Map.new(findings, fn {severity, list} ->
      {severity,
       Enum.map(list, fn {details, finding, metadata, reference} ->
         {details, %{finding | fun_source: Map.get(sources, reference)}, metadata}
       end)}
    end)
  end

  def json(vsn) do
    %{high: highs, medium: meds, low: lows} = read_log(false)
    highs = normalize_json_log(highs)
    meds = normalize_json_log(meds)
    lows = normalize_json_log(lows)

    Jason.encode!(
      format_json(%{
        findings: %{high_confidence: highs, medium_confidence: meds, low_confidence: lows},
        total_findings: length(highs) + length(meds) + length(lows),
        sobelow_version: vsn
      }),
      pretty: true
    )
  end

  def sarif(vsn) do
    Jason.encode!(
      %{
        version: "2.1.0",
        "$schema":
          "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        runs: [
          %{
            tool: %{
              driver: %{
                name: "Sobelow",
                informationUri: "https://sobelow.io",
                semanticVersion: vsn,
                rules: Sobelow.rules()
              }
            },
            results: sarif_results(),
            invocations: sarif_invocations()
          }
        ]
      },
      pretty: true
    )
  end

  defp sarif_invocations do
    notifications =
      Sobelow.Scan.report().diagnostics
      |> Enum.map(fn diagnostic ->
        %{
          level: "warning",
          descriptor: %{id: Atom.to_string(diagnostic.status)},
          message: %{text: diagnostic.message}
        }
      end)

    [%{executionSuccessful: true, toolExecutionNotifications: notifications}]
  end

  def sarif_results do
    %{high: highs, medium: meds, low: lows} = read_log(false)

    highs = normalize_sarif_log(highs)
    meds = normalize_sarif_log(meds)
    lows = normalize_sarif_log(lows)

    Enum.map(highs, &format_sarif/1) ++
      Enum.map(meds, &format_sarif/1) ++ Enum.map(lows, &format_sarif/1)
  end

  def quiet do
    total = counts() |> Map.values() |> Enum.sum()
    findings = if total > 1, do: "findings", else: "finding"

    if total > 0 do
      "Sobelow: #{total} #{findings} found. Run again without --quiet to review findings."
    end
  end

  def github do
    %{high: highs, medium: meds, low: lows} = read_log(false)
    workspace = System.get_env("GITHUB_WORKSPACE")
    base = if workspace in [nil, ""], do: File.cwd!(), else: Path.expand(workspace)

    (highs ++ meds ++ lows)
    |> sort_findings()
    |> Enum.map_join("\n", &format_github(&1, base))
    |> case do
      "" -> nil
      text -> text
    end
  end

  defp format_github({_details, finding, _custom_metadata}, base) do
    properties = github_properties(finding, base)

    message =
      "Sobelow: #{finding.type} (#{finding.confidence} confidence)"
      |> escape_data()

    "::warning #{properties}::#{message}"
  end

  defp github_properties(finding, base) do
    line = positive_integer(finding.vuln_line_no)
    column = positive_integer(finding.vuln_col_no)

    properties =
      [
        {"file", github_filename(finding.filename, base)},
        {"line", line},
        {"endLine", line},
        {"col", column}
      ]

    properties
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Enum.map_join(",", fn {key, value} -> "#{key}=#{escape_property(value)}" end)
  end

  defp github_filename(nil, _base), do: nil

  defp github_filename(filename, base) do
    root = Sobelow.Scan.normalized_root()
    relative = Path.relative_to(filename, root)

    # Findings retain their historical normalized paths (including the removed
    # leading slash). Reconstruct the real path using the scan root, then make
    # only this output relative to the repository workspace.
    path =
      cond do
        Path.type(filename) == :absolute ->
          filename

        root == "" or relative != filename ->
          Path.expand(relative, Path.expand(Sobelow.Utils.get_root()))

        true ->
          Path.expand(filename)
      end

    Path.relative_to(path, base)
  end

  defp positive_integer(value) when is_integer(value) and value > 0, do: value
  defp positive_integer(_value), do: 1

  defp escape_data(value) do
    value
    |> to_string()
    |> String.replace("%", "%25")
    |> String.replace("\r", "%0D")
    |> String.replace("\n", "%0A")
  end

  defp escape_property(value) do
    value
    |> escape_data()
    |> String.replace(":", "%3A")
    |> String.replace(",", "%2C")
  end

  def init(:ok) do
    {:ok,
     %{
       findings: %{high: [], medium: [], low: []},
       counts: %{high: 0, medium: 0, low: 0},
       sources: %{},
       sorted: nil
     }}
  end

  def handle_cast({:add_batch, batch}, state) do
    {findings, counts} =
      Enum.reduce(Enum.reverse(batch.entries), {state.findings, state.counts}, fn {severity,
                                                                                   entry},
                                                                                  {findings,
                                                                                   counts} ->
        {Map.update!(findings, severity, &[entry | &1]), Map.update!(counts, severity, &(&1 + 1))}
      end)

    {:noreply,
     %{
       state
       | findings: findings,
         counts: counts,
         sources: Map.merge(state.sources, batch.sources),
         sorted: nil
     }}
  end

  def handle_call(:counts, _from, state), do: {:reply, state.counts, state}

  def handle_call({:log, sources?}, _from, state) do
    sorted =
      state.sorted ||
        Map.new(state.findings, fn {severity, list} ->
          {severity, sort_findings(list)}
        end)

    sources = if sources?, do: state.sources, else: %{}
    {:reply, {sorted, sources}, %{state | sorted: sorted}}
  end

  @doc false
  # Prints every txt finding at the end of the scan, in a stable order.
  #
  # Findings used to print as they arrived, which under parallel scanning is
  # whatever order the tasks happened to finish — the same project could produce
  # a different report on each run, defeating diffing between runs.
  def print_txt do
    %{high: highs, medium: meds, low: lows} = log()

    (highs ++ meds ++ lows)
    |> sort_findings()
    |> Enum.each(fn {_details, finding, custom_metadata} ->
      case custom_metadata do
        nil -> Sobelow.Print.do_print_finding_metadata(finding)
        headers -> Sobelow.Print.do_print_custom_finding_metadata(finding, headers)
      end
    end)
  end

  # Location first, so a report reads in file order. The fingerprint is a final
  # tiebreaker so that two findings sharing a location still sort stably.
  defp sort_findings(findings) do
    Enum.sort_by(findings, fn entry ->
      finding = elem(entry, 1)
      {finding.filename, finding.vuln_line_no, finding.type, finding.fingerprint}
    end)
  end

  def format_json(map) when is_map(map) do
    map |> Enum.map(fn {k, v} -> {k, format_json(v)} end) |> Enum.into(%{})
  end

  def format_json(l) when is_list(l) do
    l |> Enum.map(&format_json(&1))
  end

  def format_json({_, _, _} = var) do
    details = {var, [], []} |> Macro.to_string()
    "\"#{details}\""
  end

  def format_json(n), do: n

  defp format_sarif(finding) do
    [mod, _] = String.split(finding.type, ":", parts: 2)
    mod_struct = Sobelow.get_mod(mod)

    # `get_mod/1` returns the finding module or nil. Unregistered finding types
    # (and category modules, which have no `id/0`) get a null ruleId.
    rule_id =
      if mod_struct != nil and Code.ensure_loaded?(mod_struct) and
           function_exported?(mod_struct, :id, 0) do
        apply(mod_struct, :id, [])
      end

    %{
      ruleId: rule_id,
      message: %{
        text: finding.type
      },
      locations: [
        %{
          physicalLocation: %{
            artifactLocation: %{
              uri: sarif_uri(finding.filename)
            },
            region: %{
              startLine: sarif_num(finding.vuln_line_no),
              startColumn: sarif_num(finding.vuln_col_no),
              endLine: sarif_num(finding.vuln_line_no),
              endColumn: sarif_num(finding.vuln_col_no)
            }
          }
        }
      ],
      partialFingerprints: %{
        primaryLocationLineHash: finding.fingerprint
      },
      level: to_level(finding.confidence)
    }
  end

  defp to_level(:high), do: "error"
  defp to_level(_), do: "warning"

  # Only SARIF locations are rewritten. JSON filenames and the underlying
  # Finding stay unchanged because both are part of existing skip workflows.
  defp sarif_uri(filename) do
    root = Sobelow.Scan.normalized_root()

    relative =
      if root == "" do
        filename
      else
        String.replace_prefix(filename, root <> "/", "")
      end

    if relative == filename and File.regular?("/" <> filename) do
      "file:///" <> encode_path(filename)
    else
      encode_path(relative)
    end
  end

  defp encode_path(path), do: URI.encode(path, &(&1 == ?/ or URI.char_unreserved?(&1)))

  defp sarif_num(0), do: 1
  defp sarif_num(num), do: num

  defp normalize_json_log(finding),
    do: finding |> Stream.map(fn {d, _, _} -> d end) |> normalize()

  defp normalize_sarif_log(finding),
    do: finding |> Stream.map(fn {_, f, _} -> Map.from_struct(f) end) |> normalize()

  defp normalize(l), do: l |> Enum.map(&Map.new/1)
end
