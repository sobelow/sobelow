defmodule Sobelow.EffectiveConfigTest do
  use Sobelow.ScanCase, async: false

  test "a later disabled force_ssl overrides the earlier enabled value" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, force_ssl: true
    config :basic, BasicWeb.Endpoint, force_ssl: false
    """)

    assert [_] = scan("basic") |> findings_for("Config.HTTPS")
  end

  test "one endpoint cannot satisfy HTTPS or HSTS for another" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, AdminWeb.Endpoint, https: [port: 443], force_ssl: true
    config :basic, BasicWeb.Endpoint, https: false, force_ssl: false
    """)

    assert [_] = scan("basic") |> findings_for("Config.HTTPS")

    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, AdminWeb.Endpoint, https: [port: 443], force_ssl: true
    config :basic, BasicWeb.Endpoint, https: [port: 444], force_ssl: false
    """)

    assert [_] = scan("basic") |> production_hsts()
  end

  test "dynamic HTTPS and HSTS settings are reported at low confidence" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, https: transport_options(), force_ssl: ssl_options()
    """)

    report = scan("basic")
    assert [%{"confidence" => "low"}] = findings_for(report, "Config.HTTPS")
    assert [%{"confidence" => "low"}] = production_hsts(report)
  end

  test "keyword overrides merge before HSTS is checked" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, https: [port: 443], force_ssl: [hsts: true]
    config :basic, BasicWeb.Endpoint, force_ssl: [rewrite_on: [:x_forwarded_proto]]
    config :basic, BasicWeb.Endpoint, force_ssl: [hsts: false]
    """)

    assert [_] = scan("basic") |> production_hsts()
  end

  test "conditional endpoint configuration remains unknown" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, https: [port: 443], force_ssl: true
    if custom_environment?() do
      config :basic, BasicWeb.Endpoint, https: false, force_ssl: false
    end
    """)

    assert [%{"confidence" => "low"}] = scan("basic") |> findings_for("Config.HTTPS")
  end

  test "conditional WebSocket origin defaults are low confidence" do
    temp_fixture_file("basic", "lib/basic_web/endpoint.ex", """
    defmodule BasicWeb.Endpoint do
      use Phoenix.Endpoint, otp_app: :basic
      socket "/live", Phoenix.LiveView.Socket, websocket: []
    end
    """)

    temp_fixture_file("basic", "config/runtime.exs", """
    if custom_environment?() do
      config :basic, BasicWeb.Endpoint, check_origin: false
    end
    """)

    assert [%{"confidence" => "low"}] = scan("basic") |> findings_for("Config.CSWH")
  end

  defp production_hsts(report) do
    findings_for(report, "Config.HSTS") |> Enum.filter(&(Path.basename(&1["file"]) == "prod.exs"))
  end
end
