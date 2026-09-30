defmodule Sobelow.Vuln.Coherence do
  @moduledoc """
  # Coherence Version Vulnerable to Privilege Escalation

  For more information visit:
  https://github.com/advisories/GHSA-mrq8-53r4-3j5m

  Coherence checks can be ignored with the following command:

      $ mix sobelow -i Vuln.Coherence
  """
  alias Sobelow.Vuln

  @uid 22
  @finding_type "Vuln.Coherence: Known Vulnerable Dependency - Update Coherence"

  use Sobelow.Finding

  @vuln_vsn ["<=0.5.1"]

  def run(root) do
    case Vuln.dependency_version(root, "coherence") do
      {plug_conf, vsn} ->
        case Version.parse(vsn) do
          {:ok, vsn} ->
            if Enum.any?(@vuln_vsn, fn v -> Version.match?(vsn, v) end) do
              Vuln.print_finding(
                plug_conf,
                vsn,
                "Coherence",
                "Permissive parameters and privilege escalation",
                "CVE-2018-20301",
                "Coherence"
              )
            end

          _ ->
            nil
        end

      nil ->
        nil
    end
  end
end
