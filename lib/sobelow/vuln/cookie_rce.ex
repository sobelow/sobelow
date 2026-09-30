defmodule Sobelow.Vuln.CookieRCE do
  @moduledoc """
  # Plug Version Vulnerable to Arbitrary Code Execution in Cookie Serialization

  For more information visit:
  https://github.com/advisories/GHSA-5v4m-c73v-c7gq

  Cookie RCE checks can be ignored with the following command:

      $ mix sobelow -i Vuln.CookieRCE
  """
  alias Sobelow.Vuln

  @uid 23
  @finding_type "Vuln.CookieRCE: Known Vulnerable Dependency - Update Plug"

  use Sobelow.Finding

  # we could _probably_ remove some of these versions since if Sobelow is running,
  # it means there is a minimum version of Elixir on the system which the lower
  # versions of Plug wouldn't support - will leave for now to reflect CVE
  @vuln_vsn ~w(1.3.1 1.3.0 1.2.2 1.2.1 1.2.0 1.1.6 1.1.5 1.1.4 1.1.3 1.1.2 1.1.1 1.1.0 1.0.3 1.0.2 1.0.1 1.0.0)

  def run(root) do
    case Vuln.dependency_version(root, "plug") do
      {plug_conf, vsn} when vsn in @vuln_vsn ->
        Vuln.print_finding(
          plug_conf,
          vsn,
          "Plug",
          "Arbitrary Code Execution in Cookie Serialization",
          "CVE-2017-1000053",
          "CookieRCE"
        )

      _ ->
        nil
    end
  end
end
