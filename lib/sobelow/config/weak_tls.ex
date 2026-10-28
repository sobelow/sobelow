defmodule Sobelow.Config.WeakTLS do
  @moduledoc """
  # Legacy TLS and SSL protocol versions

  Explicit SSL 2/3, TLS 1.0/1.1 and DTLS 1.0 selections in TLS `versions`
  options receive high confidence. These legacy protocols should be removed
  from both client and server configurations; use TLS 1.2 or 1.3 as required
  by the protocol. DTLS 1.2 is not flagged.

  Scans the same source files and production configuration as
  `Config.TLSVerify`, including nested TLS option lists and Gun maps.
  Development/test config files are excluded. Source files are scanned
  regardless of runtime environment. Dynamic versions, runtime overrides,
  cipher suites and protocol negotiation are not resolved.

  https://www.rfc-editor.org/rfc/rfc8996.html

      $ mix sobelow -i Config.WeakTLS
  """
  @uid 45
  @finding_type "Config.WeakTLS: Legacy TLS or SSL Protocol Version"
  @legacy [:sslv2, :sslv3, :tlsv1, :"tlsv1.1", :dtlsv1]
  use Sobelow.Finding
  alias Sobelow.Config.TLSOptions

  def run(dir_path, configs, files) do
    TLSOptions.run(__MODULE__, @finding_type, dir_path, configs, files)
  end

  @doc false
  def parse_def(ast, skipped_functions \\ MapSet.new()) do
    ast
    |> Parse.tls_option_calls(&weak_versions?/2, skipped_functions)
    |> Enum.map(&{&1, :high})
  end

  defp weak_versions?({:versions, versions}, %{tls?: true}) when is_list(versions),
    do: Enum.any?(versions, &(&1 in @legacy))

  defp weak_versions?(_, _), do: false
end
