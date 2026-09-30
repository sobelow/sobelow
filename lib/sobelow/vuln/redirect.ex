defmodule Sobelow.Vuln.Redirect do
  @moduledoc """
  # Phoenix Version Vulnerable to Arbitrary URL Redirection

  For more information visit:
  https://github.com/advisories/GHSA-cmfh-8f8r-fj96

  URL Redirection checks can be ignored with the following command:

      $ mix sobelow -i Vuln.Redirect
  """
  alias Sobelow.Vuln

  @uid 27
  @finding_type "Vuln.Redirect: Known Vulnerable Dependency - Update Phoenix"

  use Sobelow.Finding

  # we could _probably_ remove some of these versions since if Sobelow is running,
  # it means there is a minimum version of Elixir on the system which the lower
  # versions of Phoenix wouldn't support - will leave for now to reflect CVE
  @vuln_vsn ~w(1.0.0 1.0.1 1.0.2 1.0.3 1.0.4 1.1.0 1.1.1 1.1.2 1.1.3 1.1.4 1.1.5 1.1.6 1.2.0 1.2.1 1.3.0-rc.0)

  def run(root) do
    case Vuln.dependency_version(root, "phoenix") do
      {plug_conf, vsn} when vsn in @vuln_vsn ->
        Vuln.print_finding(
          plug_conf,
          vsn,
          "Phoenix",
          "Arbitrary URL Redirect",
          "CVE-2017-1000163",
          "Redirect"
        )

      _ ->
        nil
    end
  end
end
