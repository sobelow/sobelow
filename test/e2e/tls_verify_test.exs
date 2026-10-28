defmodule SobelowTest.E2E.TLSVerifyTest do
  use Sobelow.ScanCase, async: false

  test "reports production config and scanned source, but not dev config" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, ssl: [verify: :verify_none]
    """)

    temp_fixture_file("basic", "config/dev.exs", """
    config :basic, BasicWeb.Endpoint, ssl: [verify: :verify_none]
    """)

    temp_fixture_file("basic", "lib/basic_web/tls_client.ex", """
    defmodule BasicWeb.TLSClient do
      def fetch(url), do: HTTPoison.get(url, [], ssl: [verify: :verify_none])
    end
    """)

    findings = scan("basic") |> findings_for("Config.TLSVerify")
    assert length(findings) == 2
    assert Enum.all?(findings, &(&1["confidence"] == "high"))
    refute Enum.any?(findings, &String.ends_with?(&1["file"], "dev.exs"))
    assert Enum.any?(findings, &String.ends_with?(&1["file"], "prod.exs"))
    assert Enum.any?(findings, &String.ends_with?(&1["file"], "tls_client.ex"))
  end

  test "finds Hackney WebTransport and Gun map options in source" do
    temp_fixture_file("basic", "lib/basic_web/tls_client.ex", """
    defmodule BasicWeb.TLSClient do
      def webtransport(url), do: :hackney.wt_connect(url, verify: :verify_none)

      def gun(host),
        do: :gun.open(host, 443, %{transport: :tls, tls_opts: [verify: :verify_none]})
    end
    """)

    findings = scan("basic") |> findings_for("Config.TLSVerify")
    assert length(findings) == 2
    assert Enum.sort(Enum.map(findings, & &1["line"])) == [2, 5]
  end

  test "supports ignore and SARIF registration" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, ssl: [verify: :verify_none]
    """)

    assert [_] = scan("basic") |> findings_for("Config.TLSVerify")
    assert [] = scan("basic", ignored: ["Config.TLSVerify"]) |> findings_for("Config.TLSVerify")

    {output, _} = scan_io("basic", format: "sarif")
    [run] = Jason.decode!(output)["runs"]
    assert Enum.any?(run["results"], &(&1["ruleId"] == "SBLW034"))
  end

  test "reports Hackney atom and keyword options without flagging false" do
    temp_fixture_file("basic", "lib/hackney_client.ex", """
    defmodule HackneyClient do
      def atom(url), do: :hackney.get(url, [], <<>>, [:insecure])
      def keyword(url), do: :hackney.get(url, [], <<>>, insecure: true)
      def wrapper(url), do: HTTPoison.get(url, [], hackney: [insecure: true])
      def safe(url), do: :hackney.get(url, [], <<>>, insecure: false)
    end
    """)

    found = scan("basic", only: ["Config.TLSVerify"]) |> findings_for("Config.TLSVerify")
    assert Enum.sort(Enum.map(found, & &1["line"])) == [2, 3, 4]
  end

  test "server-side and unknown SSL roles receive low confidence" do
    temp_fixture_file("basic", "lib/tls_server.ex", """
    defmodule TLSServer do
      def server(), do: :ssl.listen(443, verify: :verify_none)
      def handshake(socket), do: :ssl.handshake(socket, verify: :verify_none)
      def unknown(socket), do: :ssl.setopts(socket, verify: :verify_none)
      def client(host), do: :ssl.connect(host, 443, verify: :verify_none)
    end
    """)

    found = scan("basic", only: ["Config.TLSVerify"]) |> findings_for("Config.TLSVerify")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"]})) ==
             [{2, "low"}, {3, "low"}, {4, "low"}, {5, "high"}]
  end

  test "saved skips apply only to the original TLS call and distinguish columns" do
    original = """
    defmodule TLSFingerprint do
      def fetch(url), do: HTTPoison.get(url, [], ssl: [verify: :verify_none])
    end
    """

    path = temp_fixture_file("basic", "lib/tls_fingerprint.ex", original)
    assert [_] = scan("basic", only: ["Config.TLSVerify"]) |> findings_for("Config.TLSVerify")
    [{_, old, _}] = Sobelow.FindingLog.log().high
    temp_fixture_file("basic", ".sobelow-skips", old.fingerprint <> "\n")

    assert [] =
             scan("basic", only: ["Config.TLSVerify"], skip: true)
             |> findings_for("Config.TLSVerify")

    File.write!(
      path,
      String.replace(original, "HTTPoison.get(url, [], ssl:", "Other.get(url, [], ssl:")
    )

    assert [_] =
             scan("basic", only: ["Config.TLSVerify"], skip: true)
             |> findings_for("Config.TLSVerify")

    [{_, changed, _}] = Sobelow.FindingLog.log().high
    refute old.fingerprint == changed.fingerprint

    File.write!(path, """
    defmodule TLSFingerprint do
      def fetch(url), do: {:ssl.connect(url, 443, verify: :verify_none), :ssl.connect(url, 443, verify: :verify_none)}
    end
    """)

    assert [_, _] =
             scan("basic", only: ["Config.TLSVerify"], skip: true)
             |> findings_for("Config.TLSVerify")

    fingerprints = Enum.map(Sobelow.FindingLog.log().high, fn {_, f, _} -> f.fingerprint end)
    assert length(Enum.uniq(fingerprints)) == 2

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["Config.TLSVerify"], format: format, verbose: true)
      assert output =~ if(format == "sarif", do: "SBLW034", else: "Config.TLSVerify")
    end
  end

  for skip <- ["Config.TLSVerify", "Config"] do
    test "honors #{skip} function comments only with --skip" do
      temp_fixture_file("basic", "lib/basic_web/tls_client.ex", """
      defmodule BasicWeb.TLSClient do
        @tls [ssl: [verify: :verify_none]]

        # sobelow_skip ["#{unquote(skip)}"]
        def skipped(url), do: HTTPoison.get(url, [], ssl: [verify: :verify_none])

        # sobelow_skip ["Traversal"]
        def reported(url), do: HTTPoison.get(url, [], ssl: [verify: :verify_none])

        # sobelow_skip ["#{unquote(skip)}"]
        defp private_skipped(url), do: :hackney.get(url, [], <<>>, [:insecure])

        defmodule Nested do
          def reported(url), do: :hackney.get(url, [], <<>>, [:insecure])
        end
      end
      """)

      findings = scan("basic", skip: true) |> findings_for("Config.TLSVerify")
      assert Enum.sort(Enum.map(findings, & &1["line"])) == [2, 8, 14]

      findings = scan("basic") |> findings_for("Config.TLSVerify")
      assert Enum.sort(Enum.map(findings, & &1["line"])) == [2, 5, 8, 11, 14]
    end
  end
end
