defmodule SobelowTest.Config.TLSVerifyTest do
  use ExUnit.Case, async: true

  alias Sobelow.Config.TLSVerify

  for call <- [
        ~S'HTTPoison.get(url, [], ssl: [verify: :verify_none])',
        ~S':ssl.connect(host, port, [verify: :verify_none])',
        ~S':hackney.get(url, [], <<>>, [:insecure])',
        ~S':hackney.wt_connect(url, verify: :verify_none)',
        ~S':hackney.get(url, [], <<>>, ssl_options: [verify: :verify_none])',
        ~S':gun.open(host, port, %{transport: :tls, tls_opts: [verify: :verify_none]})',
        ~S'HTTPoison.get(url, [], hackney: [:insecure])',
        ~S'Mint.HTTP.connect(:https, host, port, transport_opts: [verify: :verify_none])'
      ] do
    test "finds disabled verification in #{call}" do
      ast = Code.string_to_quoted!("def fetch(url, host, port), do: #{unquote(call)}")
      assert [_] = TLSVerify.insecure_calls(ast)
    end
  end

  for call <- [
        ~S'HTTPoison.get(url, [], ssl: [verify: :verify_peer])',
        ~S':hackney.get(url, [], <<>>, [follow_redirect: true])',
        ~S':hackney.get(url, [], <<>>, [verify: :verify_none])',
        ~S'HTTPoison.get(url, [], hackney: [pool: :insecure])',
        ~S'other_call(verify: :verify_none)',
        ~S'other_call(%{verify: :verify_none})',
        ~S':gun.open(host, port, %{transport: :tls, tls_opts: [verify: :verify_peer]})',
        ~S'other_call(:insecure)',
        ~S'HTTPoison.get(url, [], ssl: options)'
      ] do
    test "ignores unrelated options in #{call}" do
      ast = Code.string_to_quoted!("def fetch(url), do: #{unquote(call)}")
      assert [] = TLSVerify.insecure_calls(ast)
    end
  end

  test "reports a nested unsafe call once, at its own line" do
    ast =
      Code.string_to_quoted!(
        "def fetch(url), do: wrapper(HTTPoison.get(url, [], ssl: [verify: :verify_none]))"
      )

    assert [call] = TLSVerify.insecure_calls(ast)
    assert Macro.to_string(call) =~ "HTTPoison.get"
  end
end
