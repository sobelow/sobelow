defmodule Sobelow.FindingLog do
  @moduledoc false

  use GenServer

  def start_link do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def add(finding, severity) do
    GenServer.cast(__MODULE__, {:add, finding, severity})
  end

  def log do
    GenServer.call(__MODULE__, :log)
  end

  def json(vsn) do
    %{high: highs, medium: meds, low: lows} = log()
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
          "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
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
            results: sarif_results()
          }
        ]
      },
      pretty: true
    )
  end

  def sarif_results do
    %{high: highs, medium: meds, low: lows} = log()

    highs = normalize_sarif_log(highs)
    meds = normalize_sarif_log(meds)
    lows = normalize_sarif_log(lows)

    Enum.map(highs, &format_sarif/1) ++
      Enum.map(meds, &format_sarif/1) ++ Enum.map(lows, &format_sarif/1)
  end

  def quiet do
    total = total(log())
    findings = if total > 1, do: "findings", else: "finding"

    if total > 0 do
      "Sobelow: #{total} #{findings} found. Run again without --quiet to review findings."
    end
  end

  @doc false
  def github do
    %{high: highs, medium: meds, low: lows} = log()

    (highs ++ meds ++ lows)
    |> sort_findings()
    |> Enum.map_join("\n", &format_github/1)
  end

  defp total(%{high: highs, medium: meds, low: lows}) do
    length(highs) + length(meds) + length(lows)
  end

  defp format_github({_details, finding, _custom_metadata}) do
    level = if finding.confidence == :high, do: "error", else: "warning"

    properties =
      [
        {"file", finding.filename},
        {"line", finding.vuln_line_no},
        {"col", finding.vuln_col_no},
        {"title", finding.type}
      ]
      |> Enum.reject(fn {_key, value} -> is_nil(value) or value == 0 end)
      |> Enum.map_join(",", fn {key, value} -> "#{key}=#{escape_command_value(value)}" end)

    message =
      case finding.vuln_variable do
        nil -> finding.type
        variable -> "#{finding.type}: #{variable}"
      end

    "::#{level} #{properties}::#{escape_command_value(message)}"
  end

  defp escape_command_value(value) do
    value
    |> to_string()
    |> String.replace("%", "%25")
    |> String.replace("\r", "%0D")
    |> String.replace("\n", "%0A")
    |> String.replace(":", "%3A")
    |> String.replace(",", "%2C")
  end

  def init(:ok) do
    {:ok, %{:high => [], :medium => [], :low => []}}
  end

  def handle_cast({:add, finding, severity}, findings) do
    {:noreply, Map.update!(findings, severity, &[finding | &1])}
  end

  def handle_call(:log, _from, findings) do
    sorted = Map.new(findings, fn {severity, list} -> {severity, sort_findings(list)} end)
    {:reply, sorted, findings}
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
    Enum.sort_by(findings, fn {_details, finding, _custom_metadata} ->
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
      if (mod_struct && Code.ensure_loaded?(mod_struct)) and
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
              uri: finding.filename
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

  defp sarif_num(0), do: 1
  defp sarif_num(num), do: num

  defp normalize_json_log(finding),
    do: finding |> Stream.map(fn {d, _, _} -> d end) |> normalize()

  defp normalize_sarif_log(finding),
    do: finding |> Stream.map(fn {_, f, _} -> Map.from_struct(f) end) |> normalize()

  defp normalize(l), do: l |> Enum.map(&Map.new/1)
end
