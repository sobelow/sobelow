defmodule Sobelow.Config.HSTS do
  @moduledoc """
  # HSTS

  The HTTP Strict Transport Security (HSTS) header helps
  defend against man-in-the-middle attacks by preventing
  unencrypted connections.

  HSTS checks can be ignored with the following command:

      $ mix sobelow -i Config.HSTS
  """
  alias Sobelow.Config

  @uid 8
  @finding_type "Config.HSTS: HSTS Not Enabled"
  @ignored_files ["runtime.exs"]

  use Sobelow.Finding

  def run(dir_path, configs) do
    Enum.each(configs, fn conf ->
      unless Enum.member?(@ignored_files, conf) do
        path = dir_path <> conf

        statuses =
          Config.effective_app_configs(path)
          |> Enum.map(fn options ->
            https = Config.setting_status(Keyword.get(options, :https))
            hsts = Config.hsts_status(Keyword.get(options, :force_ssl))

            cond do
              https == :disabled or hsts == :enabled -> :enabled
              https == :unknown or hsts == :unknown -> :unknown
              true -> :disabled
            end
          end)

        cond do
          :disabled in statuses -> add_finding(path, :medium)
          :unknown in statuses -> add_finding(path, :low)
          true -> nil
        end
      end
    end)
  end

  defp add_finding(file, confidence) do
    reason = "HSTS configuration details could not be found in `#{Path.basename(file)}`."

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
        # No function, line, or variable applies to a missing HSTS setting, so
        # the header alone is the whole finding.
        Sobelow.log_finding(finding, [])

      "compact" ->
        Print.log_compact_finding(finding)

      "flycheck" ->
        Print.log_flycheck_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end
end
