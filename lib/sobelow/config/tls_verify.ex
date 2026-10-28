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

  Server-side `:ssl` calls and calls whose client/server role is unknown
  receive low confidence: disabling client-certificate authentication is
  normal for servers that do not require mutual TLS. Client connections
  with verification disabled receive high confidence.

  Ignore this check with:

      $ mix sobelow -i Config.TLSVerify
  """
  @uid 34
  @finding_type "Config.TLSVerify: TLS Certificate Verification Disabled"
  @tls_option_keys [:ssl, :ssl_options, :transport_opts, :connect_options, :tls, :tls_opts]

  use Sobelow.Finding

  def run(dir_path, configs, files) do
    Enum.each(configs, &scan_file(Path.join(dir_path, &1)))

    # Discovery already warned about unreadable source files. Reuse its cached
    # read result so this check does not report the same failure again.
    Enum.each(files, fn file ->
      if match?({:ok, _}, Sobelow.Scan.source(file.file_path)) do
        scan_file(file.file_path, skipped_functions(file))
      end
    end)
  end

  defp scan_file(path, skipped_functions \\ MapSet.new()) do
    path
    |> Parse.ast()
    |> insecure_calls(skipped_functions)
    |> Enum.each(&add_finding(path, &1))
  end

  defp skipped_functions(file) do
    for context <- file.scan_contexts,
        {{fun, skips}, _lexical} <- context.functions,
        Sobelow.get_env(:skip),
        Enum.any?(skips, &(Sobelow.get_mod(&1) in [__MODULE__, Sobelow.Config])),
        into: MapSet.new(),
        do: fun
  end

  @doc false
  def insecure_calls(ast), do: insecure_calls(ast, MapSet.new())

  defp insecure_calls(ast, skipped_functions) do
    {_, calls} =
      Macro.prewalk(ast, [], fn node, acc ->
        if MapSet.member?(skipped_functions, node) do
          {{}, acc}
        else
          collect_insecure_call(node, acc)
        end
      end)

    Enum.reverse(calls)
  end

  defp collect_insecure_call({name, _, args} = call, acc)
       when is_list(args) and name != :%{} do
    if insecure_options?(args, hackney_call?(name), direct_tls_options?(name)),
      do: {call, [call | acc]},
      else: {call, acc}
  end

  defp collect_insecure_call(node, acc), do: {node, acc}

  defp insecure_options?(options, hackney?, tls?) when is_list(options) do
    Enum.any?(options, &insecure_option?(&1, hackney?, tls?))
  end

  defp insecure_options?(_, _, _), do: false

  defp insecure_option?(options, hackney?, tls?) when is_list(options),
    do: insecure_options?(options, hackney?, tls?)

  defp insecure_option?({:%{}, _, entries}, hackney?, tls?) when is_list(entries),
    do: insecure_options?(entries, hackney?, tls?)

  defp insecure_option?({:verify, :verify_none}, _, tls?), do: tls?
  defp insecure_option?({:insecure, true}, true, _), do: true

  defp insecure_option?({key, options}, hackney?, tls?) when is_list(options),
    do: insecure_options?(options, hackney? or key == :hackney, tls? or key in @tls_option_keys)

  defp insecure_option?(:insecure, true, _), do: true
  defp insecure_option?(_, _, _), do: false

  defp hackney_call?({:., _, [:hackney, _]}), do: true
  defp hackney_call?(_), do: false

  defp direct_tls_options?({:., _, [:ssl, _]}), do: true
  defp direct_tls_options?({:., _, [:hackney, :wt_connect]}), do: true
  defp direct_tls_options?(_), do: false

  defp confidence({{:., _, [:ssl, name]}, _, _}) when name != :connect, do: :low
  defp confidence(_), do: :high

  defp add_finding(path, call) do
    finding =
      Finding.init(@finding_type, Utils.normalize_path(path), confidence(call))
      |> Map.merge(%{
        vuln_source: call,
        vuln_line_no: Parse.get_fun_line(call),
        vuln_col_no: Parse.get_fun_column(call),
        fun_source: call
      })

    Print.add_finding(finding)
  end
end
