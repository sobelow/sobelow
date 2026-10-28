defmodule Sobelow.Config.TLSVerify do
  @moduledoc """
  # Disabled TLS certificate verification

  Reports literal `verify: :verify_none` in TLS options, including Gun's
  `tls_opts` map entries. It also catches hackney's `:insecure` and
  `insecure: true` options and
  the direct `verify` option in WebTransport connections. Disabling
  verification lets an attacker impersonate the remote server. Use
  `:verify_peer` and a trusted CA, including for self-signed services.

  Configuration in `dev.exs` and `test.exs` is excluded with the rest of
  Sobelow's config checks. Source files are scanned regardless of the
  runtime environment; review guards around development-only calls.
  Dynamically constructed options are not resolved.
  Explicit Erlang SSL and Hackney imports are resolved within their scope.

  Server-side `:ssl` calls and calls whose client/server role is unknown
  receive low confidence: disabling client-certificate authentication is
  normal for servers that do not require mutual TLS. Client connections
  with verification disabled receive high confidence.

  Ignore this check with:

      $ mix sobelow -i Config.TLSVerify
  """
  @uid 34
  @finding_type "Config.TLSVerify: TLS Certificate Verification Disabled"

  use Sobelow.Finding
  alias Sobelow.Config.TLSOptions

  def run(dir_path, configs, files) do
    TLSOptions.run(__MODULE__, @finding_type, dir_path, configs, files)
  end

  @doc false
  def insecure_calls(ast) do
    ast |> parse_def() |> Enum.map(&elem(&1, 0))
  end

  @doc false
  def parse_def(ast, skipped_functions \\ MapSet.new()) do
    ast
    |> Parse.tls_option_calls(&insecure_option?/2, skipped_functions)
    |> Enum.map(&{&1, confidence(&1)})
  end

  defp insecure_option?({:verify, :verify_none}, %{tls?: true}), do: true
  defp insecure_option?({:insecure, true}, %{hackney?: true}), do: true
  defp insecure_option?(:insecure, %{hackney?: true}), do: true
  defp insecure_option?(_, _), do: false

  defp confidence({{:., _, [:ssl, name]}, _, _}) when name != :connect, do: :low

  defp confidence({name, _, _} = call) when is_atom(name) and name != :connect do
    if Sobelow.Lexical.erlang_imported?(call, :ssl), do: :low, else: :high
  end

  defp confidence(_), do: :high
end
