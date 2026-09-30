defmodule Sobelow.ConfigBehaviorTest do
  use Sobelow.CoverageCase, async: false
  alias Sobelow.Config
  alias Sobelow.Config.{CSP, CSRFRoute, CSWH}

  @tag :tmp_dir
  test "config lookups isolate application and endpoint and retain explicit false values", %{
    tmp_dir: dir
  } do
    path = Path.join(dir, "config.exs")

    File.write!(path, """
    config :basic, https: false
    config :basic, BasicWeb.Endpoint, https: true, check_origin: false
    config :other, BasicWeb.Endpoint, https: true, check_origin: true
    config :basic, OtherWeb.Endpoint, https: false
    config :basic, BasicWeb.Endpoint, port: 4000
    config :basic, BasicWeb.Endpoint, [:invalid]
    config :basic, NotEndpoint, https: true
    config :basic, :named, https: true
    config :basic, [:invalid]
    """)

    values = Config.get_app_configs(:https, path) |> Enum.map(&elem(&1, 2)) |> Enum.sort()
    assert values == [false, false, true]

    assert [{_, :check_origin, false}] =
             Config.get_endpoint_configs(:check_origin, path, [:BasicWeb, :Endpoint])

    assert Config.get_endpoint_configs(:missing, path, [:BasicWeb, :Endpoint]) == []

    assert Config.get_endpoint_configs(:https, Path.join(dir, "missing"), [:BasicWeb, :Endpoint]) ==
             []

    assert Config.get_configs_by_file(:https, Path.join(dir, "missing")) == []
  end

  test "setting status preserves uncertainty and historical helper contracts" do
    assert Config.setting_status([:invalid]) == :unknown
    assert Config.setting_status(quoted("dynamic()")) == :unknown
    assert Config.hsts_status(hsts: quoted("dynamic()")) == :unknown
    assert Config.enabled_config?({:node, :https, true})
    refute Config.enabled_config?({:node, :https, false})
    assert Config.hsts_enabled?({:node, :force_ssl, true})
    assert Config.hsts_enabled?({:node, :force_ssl, []})
    refute Config.hsts_enabled?({:node, :force_ssl, hsts: false})
    refute Config.hsts_enabled?({:node, :force_ssl, [:invalid]})
    assert Config.get_version({:@, [], nil}, :previous) == {{:@, [], nil}, :previous}
  end

  test "accepts sigils and non-plug expressions do not hide router security settings" do
    assert Config.get_plug_accepts(quoted("plug :accepts, ~w(html json)")) == ["html", "json"]
    assert Config.get_plug_accepts(quoted("plug :other")) == []
    assert Config.get_plug_list(quoted("not_a_plug()")) == []
    assert Config.get_plug_list(nil) == []
  end

  @tag :tmp_dir
  test "unreadable config directories warn without aborting checks", %{tmp_dir: dir} do
    File.write!(Path.join(dir, "config"), "not a directory")
    assert capture_io(:stderr, fn -> Config.fetch(dir <> "/", [], []) end) =~ "Could not read"
    assert logged_findings() == []
  end

  @tag :tmp_dir
  test "explicit routers outside the project retain their absolute locations", %{tmp_dir: dir} do
    root = Path.join(dir, "project")
    File.mkdir_p!(root)
    router = Path.join(dir, "router.ex")
    File.write!(router, "pipeline :browser do\n plug :fetch_session\nend")
    Config.fetch(root <> "/", [router], [])
    assert [%Finding{filename: filename}] = logged_findings()
    assert filename == Sobelow.Utils.normalize_path(router)
  end

  @tag :tmp_dir
  test "a nonliteral endpoint module name remains scannable", %{tmp_dir: dir} do
    path = Path.join(dir, "endpoint.ex")

    File.write!(
      path,
      "defmodule module_name() do\n socket \"/socket\", UserSocket, websocket: [check_origin: false]\nend"
    )

    CSWH.run(path)
    assert [%Finding{confidence: :high, vuln_line_no: 2}] = logged_findings()
  end

  test "CSP handles missing, nil, malformed and nonliteral custom headers conservatively" do
    for {headers, confidence} <- [
          {~s(%{"content-security-policy" => nil}), :high},
          {~s(%{other: "header"}), :high},
          {"headers()", :low},
          {"@headers", :low}
        ] do
      pipeline =
        quoted("pipeline :browser do\n plug :put_secure_browser_headers, #{headers}\nend")

      meta = %{module_attrs: [{:unrelated, [], [true]}]}
      assert {true, ^confidence, _, ^pipeline} = CSP.check_vuln_pipeline(pipeline, meta)
    end
  end

  test "scope extraction supports all public Phoenix scope forms" do
    for source <- [
          ~s|scope "/", BasicWeb, as: :basic do\n get "/", controller(), :show\nend|,
          ~s(scope alias: BasicWeb do\n get "/", PageController, :show\nend),
          ~s(scope "/", as: :basic do\n get "/", PageController, :show\nend),
          ~s(scope "/", nil do\n get "/", PageController, :show\nend)
        ] do
      [routes] = CSRFRoute.combine_scopes([quoted(source)])
      assert List.flatten(routes) != []
    end

    routes = quoted(~s|get "/", controller(), :show| <> "\n" <> ~s|post "/", controller(), :show|)

    findings =
      CSRFRoute.route_findings(routes, Finding.init("Config.CSRFRoute: CSRF", "router.ex", :high))
      |> Enum.to_list()

    assert [%Finding{fun_name: :show}] = findings
  end

  test "WebSocket options handle defaults, disabled transports and unresolved settings" do
    for options <- [
          "websocket: true",
          "websocket: false",
          "[]",
          "longpoll: true",
          "websocket: [check_origin: true]"
        ] do
      socket = quoted("socket \"/socket\", UserSocket, #{options}")
      assert CSWH.check_socket(socket) == {false, :high}
    end

    assert CSWH.check_socket(quoted(~s(socket "/socket", UserSocket))) == {false, :high}

    for options <- [
          "websocket: dynamic()",
          "websocket: [:invalid]",
          "websocket: [check_origin: []]",
          "websocket: [check_origin: [dynamic()]]"
        ] do
      assert CSWH.check_socket(quoted("socket \"/socket\", UserSocket, #{options}")) ==
               {true, :low}
    end
  end
end
