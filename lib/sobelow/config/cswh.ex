defmodule Sobelow.Config.CSWH do
  @moduledoc """
  # Cross-Site Websocket Hijacking

  Websocket connections are not bound by the same-origin policy.
  Connections that do not validate the origin may leak information
  to an attacker.

  More information can be found here: https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html

  Cross-Site Websocket Hijacking checks can be disabled with
  the following command:

      $ mix sobelow -i Config.CSWH
  """
  @uid 6
  @finding_type "Config.CSWH: Cross-Site Websocket Hijacking"

  use Sobelow.Finding
  alias Sobelow.Config

  def run(endpoint) do
    ast = Parse.ast(endpoint)
    default = endpoint_origin(ast)

    ast
    |> Parse.get_funs_of_type(:socket)
    |> handle_sockets(endpoint, default)
  end

  defp endpoint_origin(ast) do
    module =
      ast
      |> Parse.get_funs_of_type(:defmodule)
      |> Enum.find_value(fn
        {:defmodule, _, [{:__aliases__, _, segments}, _]} -> segments
        _ -> nil
      end)

    if module do
      root = Sobelow.Utils.get_root()

      values =
        ["config.exs", "prod.exs", "runtime.exs"]
        |> Enum.flat_map(fn file ->
          case Config.effective_endpoint_config(
                 :check_origin,
                 Path.join([root, "config", file]),
                 module
               ) do
            {:ok, value} -> [value]
            :error -> []
          end
        end)

      List.last(values)
    end
  end

  defp handle_sockets(sockets, endpoint, default) do
    Enum.each(sockets, fn socket ->
      check_socket_with_default(socket, default)
      |> add_finding(socket, endpoint)
    end)
  end

  def check_socket(socket), do: check_socket_with_default(socket, nil)

  defp check_socket_with_default({_, _, [_, _, options]}, default),
    do: check_socket_options(options, default)

  defp check_socket_with_default({_, _, [_, _]}, default),
    do: check_websocket_options([], default)

  defp check_socket_with_default(_, _), do: {false, :high}

  defp check_socket_options([{:websocket, options} | _], default) when is_list(options) do
    if Keyword.keyword?(options) do
      check_websocket_options(options, default)
    else
      {true, :low}
    end
  end

  defp check_socket_options([{:websocket, false} | _], _default), do: {false, :high}

  defp check_socket_options([{:websocket, true} | _], default),
    do: check_websocket_options([], default)

  defp check_socket_options([{:websocket, _dynamic} | _], _default), do: {true, :low}

  defp check_socket_options([_ | t], default), do: check_socket_options(t, default)
  defp check_socket_options([], default), do: check_websocket_options([], default)

  defp check_websocket_options(options, default) do
    origin = Keyword.get(options, :check_origin, default)

    case origin do
      false ->
        if options[:check_csrf] == true, do: {true, :low}, else: {true, :high}

      true ->
        {false, :high}

      :conn ->
        {false, :high}

      nil ->
        {false, :high}

      origins when is_list(origins) ->
        if origins != [] and Enum.all?(origins, &is_binary/1),
          do: {false, :high},
          else: {true, :low}

      _ ->
        {true, :low}
    end
  end

  defp add_finding(nil, _, _), do: nil
  defp add_finding({false, _}, _, _), do: nil

  defp add_finding({true, confidence}, socket, endpoint) do
    finding = Finding.init(@finding_type, Utils.normalize_path(endpoint), confidence)

    finding =
      %{
        finding
        | vuln_source: :highlight_all,
          vuln_line_no: Parse.get_fun_line(socket),
          vuln_col_no: Parse.get_fun_column(socket),
          fun_source: socket
      }
      |> Finding.fetch_fingerprint()

    file_header = "File: #{finding.filename}"
    line_header = "Line: #{finding.vuln_line_no}"

    case Sobelow.format() do
      "json" ->
        json_finding = [
          type: finding.type,
          file: finding.filename,
          line: finding.vuln_line_no
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(
          finding,
          [file_header, line_header]
        )

      "compact" ->
        Print.log_compact_finding(finding)

      "flycheck" ->
        Print.log_flycheck_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end
end
