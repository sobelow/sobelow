defmodule Sobelow.HTTPSAppConfigTest do
  use Sobelow.ScanCase, async: false

  for setting <- ["force_ssl: [rewrite_on: [:x_forwarded_proto]]", "https: [port: 443]"],
      position <- [:before, :after] do
    test "unrelated application config #{position} an endpoint with #{setting} is ignored" do
      endpoint = "config :basic, BasicWeb.Endpoint, #{unquote(setting)}\n"
      unrelated = ~s|config :basic, api_key: System.get_env("KEY")\n|

      source =
        if unquote(position) == :before,
          do: unrelated <> endpoint,
          else: endpoint <> unrelated

      temp_fixture_file("basic", "config/prod.exs", endpoint)
      original = scan("basic")
      assert [] == findings_for(original, "Config.HTTPS")

      temp_fixture_file("basic", "config/prod.exs", source)
      report = scan("basic")
      assert [] == findings_for(report, "Config.HTTPS")
      assert findings_for(report, "Config.HSTS") == findings_for(original, "Config.HSTS")
    end
  end

  test "unrelated application settings alone still report missing HTTPS" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, api_key: System.get_env("KEY")
    """)

    assert [%{"confidence" => "high"}] = scan("basic") |> findings_for("Config.HTTPS")
  end

  test "explicit historical application-level transport settings remain supported" do
    path =
      temp_fixture_file("basic", "config/prod.exs", """
      config :basic, force_ssl: true
      config :basic, api_key: System.get_env("KEY")
      """)

    assert [] == scan("basic") |> findings_for("Config.HTTPS")

    File.write!(path, "config :basic, force_ssl: false\n")
    assert [%{"confidence" => "high"}] = scan("basic") |> findings_for("Config.HTTPS")

    File.write!(path, "config :basic, https: [port: 443]\n")
    assert [] == scan("basic") |> findings_for("Config.HTTPS")

    File.write!(path, "config :basic, force_ssl: transport_options()\n")
    assert [%{"confidence" => "low"}] = scan("basic") |> findings_for("Config.HTTPS")
  end

  test "application-level HTTPS cannot satisfy an insecure endpoint" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, https: [port: 443]
    config :basic, BasicWeb.Endpoint, http: [port: 80]
    """)

    assert [%{"confidence" => "high"}] = scan("basic") |> findings_for("Config.HTTPS")
  end

  test "unrelated settings cannot hide a second insecure endpoint" do
    temp_fixture_file("basic", "config/prod.exs", """
    config :basic, BasicWeb.Endpoint, force_ssl: true
    config :basic, api_key: System.get_env("KEY")
    config :basic, AdminWeb.Endpoint, http: [port: 80]
    """)

    assert [%{"confidence" => "high"}] = scan("basic") |> findings_for("Config.HTTPS")
  end
end
