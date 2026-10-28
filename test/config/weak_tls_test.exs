defmodule SobelowTest.Config.WeakTLSTest do
  use ExUnit.Case, async: true
  alias Sobelow.Config.WeakTLS

  for source <- [
        ~S':ssl.connect(host, 443, versions: [:tlsv1])',
        ~S':ssl.listen(443, versions: [:"tlsv1.1", :"tlsv1.2"])',
        ~S':ssl.connect(host, 443, versions: [:sslv3])',
        ~S':ssl.connect(host, 443, versions: [:sslv2])',
        ~S':ssl.connect(host, 443, protocol: :dtls, versions: [:dtlsv1])',
        ~S'HTTPoison.get(url, [], ssl: [versions: [:tlsv1]])',
        ~S'Mint.HTTP.connect(:https, host, 443, transport_opts: [versions: [:"tlsv1.1"]])',
        ~S':gun.open(host, 443, %{transport: :tls, tls_opts: [versions: [:tlsv1]]})',
        ~S'config :client, ssl_options: [versions: [:tlsv1, dynamic]]'
      ] do
    test "reports once for #{source}" do
      ast = Code.string_to_quoted!(unquote(source))
      assert [{_, :high}] = WeakTLS.parse_def(ast)
    end
  end

  for source <- [
        ~S':ssl.connect(host, 443, versions: [:"tlsv1.2", :"tlsv1.3"])',
        ~S':ssl.connect(host, 443, protocol: :dtls, versions: [:"dtlsv1.2"])',
        ~S':ssl.connect(host, 443, versions: versions)',
        ~S':ssl.connect(host, 443, versions: [])',
        ~S'other_call(versions: [:tlsv1])',
        ~S'other_call(%{versions: [:tlsv1]})',
        ~S':gun.open(host, 443, %{tls_opts: [versions: [:"tlsv1.3"]]})'
      ] do
    test "omits #{source}" do
      assert [] = unquote(source) |> Code.string_to_quoted!() |> WeakTLS.parse_def()
    end
  end
end
