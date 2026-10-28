defmodule SobelowTest.E2E.WeakTLSTest do
  use Sobelow.ScanCase, async: false

  test "scans production config and source, respecting dev and file exclusions" do
    for file <- ["prod.exs", "dev.exs", "test.exs"] do
      temp_fixture_file("basic", "config/" <> file, """
      config :basic, ssl: [versions: [:tlsv1]]
      """)
    end

    ignored =
      temp_fixture_file("basic", "lib/ignored_tls.ex", """
      defmodule IgnoredTLS do
        def connect(host), do: :ssl.connect(host, 443, versions: [:tlsv1])
      end
      """)

    temp_fixture_file("basic", "lib/legacy_tls.ex", """
    defmodule LegacyTLS do
      def connect(host), do: :ssl.connect(host, 443, versions: [:"tlsv1.1"])
      def modern(host), do: :ssl.connect(host, 443, versions: [:"tlsv1.3"])
    end
    """)

    found =
      scan("basic", only: ["Config.WeakTLS"], ignored_files: [Path.expand(ignored)])
      |> findings_for("Config.WeakTLS")

    assert length(found) == 2
    assert Enum.all?(found, &(&1["confidence"] == "high"))
    assert Enum.any?(found, &String.ends_with?(&1["file"], "prod.exs"))
    assert Enum.any?(found, &String.ends_with?(&1["file"], "legacy_tls.ex"))
  end

  test "check-specific and category skips retain independent TLS checks" do
    temp_fixture_file("basic", "lib/skipped_tls.ex", """
    defmodule SkippedTLS do
      # sobelow_skip ["Config.WeakTLS"]
      def verification(host), do: :ssl.connect(host, 443, verify: :verify_none, versions: [:tlsv1])
      # sobelow_skip ["Config"]
      def skipped(host), do: :ssl.connect(host, 443, verify: :verify_none, versions: [:tlsv1])
      def reported(host), do: :ssl.connect(host, 443, verify: :verify_none, versions: [:tlsv1])
    end
    """)

    report = scan("basic", only: ["Config.WeakTLS", "Config.TLSVerify"], skip: true)
    assert Enum.map(findings_for(report, "Config.WeakTLS"), & &1["line"]) == [6]
    assert Enum.map(findings_for(report, "Config.TLSVerify"), & &1["line"]) == [3, 6]
    assert [] = scan("basic", ignored: ["Config"]) |> findings_for("Config.WeakTLS")

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["Config.WeakTLS"], format: format)
      assert output =~ if(format == "sarif", do: "SBLW045", else: "Config.WeakTLS")
    end
  end

  test "malformed sources remain nonfatal for both TLS checks" do
    temp_fixture_file("basic", "lib/broken_tls.ex", "defmodule BrokenTLS do\n(")
    {output, stderr} = scan_io("basic", only: ["Config.WeakTLS", "Config.TLSVerify"])
    assert Jason.decode!(output)["total_findings"] == 0
    assert stderr =~ "broken_tls.ex"
    assert stderr =~ "skipping it"
  end
end
