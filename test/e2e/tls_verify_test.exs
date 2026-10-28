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
