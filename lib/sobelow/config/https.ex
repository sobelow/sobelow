defmodule Sobelow.Config.HTTPS do
  @moduledoc """
  # HTTPS

  Without HTTPS, attackers in a privileged network position can
  intercept and modify traffic.

  Sobelow detects missing HTTPS by checking the prod
  configuration.

  HTTPS checks can be ignored with the following command:

      $ mix sobelow -i Config.HTTPS
  """
  alias Sobelow.Config

  @uid 9
  @finding_type "Config.HTTPS: HTTPS Not Enabled"

  use Sobelow.Finding

  def run(dir_path, configs) do
    path = dir_path <> "prod.exs"

    if File.exists?(path) && Enum.member?(configs, "prod.exs") do
      statuses =
        Config.effective_app_configs(path)
        |> Enum.map(fn options ->
          states =
            Enum.map([:https, :force_ssl], &Config.setting_status(Keyword.get(options, &1)))

          cond do
            :enabled in states -> :enabled
            :unknown in states -> :unknown
            true -> :disabled
          end
        end)

      cond do
        statuses == [] or :disabled in statuses -> add_finding(path, :high)
        :unknown in statuses -> add_finding(path, :low)
        true -> nil
      end
    end
  end

  defp add_finding(file, confidence) do
    reason = "HTTPS configuration details could not be found in `prod.exs`."

    finding =
      %Finding{
        type: @finding_type,
        filename: Utils.normalize_path(file),
        fun_source: nil,
        vuln_source: reason,
        vuln_line_no: 0,
        vuln_col_no: 0,
        confidence: confidence
      }
      |> Finding.fetch_fingerprint()

    case Sobelow.format() do
      "json" ->
        json_finding = [
          type: finding.type,
          file: finding.filename,
          line: finding.vuln_line_no
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(finding, ["File: #{finding.filename}"])

      "compact" ->
        Print.log_compact_finding(finding)

      "flycheck" ->
        Print.log_flycheck_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end
end
