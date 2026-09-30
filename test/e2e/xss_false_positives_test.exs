defmodule SobelowTest.E2E.XSSFalsePositivesTest do
  use Sobelow.ScanCase, async: false

  test "local raw helpers are clean while Phoenix raw calls still report" do
    path =
      temp_fixture_file("basic", "lib/raw_helpers.ex", """
      defmodule RawHelpers do
        alias Phoenix.HTML, as: PH
        def local(arg), do: raw(arg)
        def raw(arg), do: 42
        def unsafe(arg), do: PH.raw(arg)
      end
      """)

    assert [%{"line" => 5, "variable" => "arg", "confidence" => "low"}] =
             scan("basic")
             |> findings_for("XSS.Raw")
             |> Enum.filter(&String.ends_with?(&1["file"], path))
  end

  test "the reported JSON header pattern is clean while HTML responses still report" do
    path =
      temp_fixture_file("basic", "lib/basic_web/controllers/header_controller.ex", """
      defmodule BasicWeb.HeaderController do
        use BasicWeb, :controller
        alias Plug.Conn, as: PC

        def json(conn, params) do
          conn
          |> put_resp_header("content-type", "application/json")
          |> send_resp(200, Jason.encode!(%{name: params["name"]}))
        end

        def html(conn, params) do
          conn
          |> PC.put_resp_header("content-type", "text/html")
          |> PC.send_resp(200, params["name"])
        end
      end
      """)

    assert [%{"line" => 14, "variable" => "params", "confidence" => "high"}] =
             scan("basic")
             |> findings_for("XSS.SendResp")
             |> Enum.filter(&String.ends_with?(&1["file"], path))
  end

  test "custom imported setters cannot hide XSS in the full scan" do
    path =
      temp_fixture_file("basic", "lib/custom_headers.ex", """
      defmodule CustomHeaders do
        def put_resp_header(conn, _name, _value), do: conn
      end
      defmodule Response do
        import Plug.Conn, only: [send_resp: 3]
        import CustomHeaders, only: [put_resp_header: 3]
        def unsafe(conn, input) do
          conn |> put_resp_header("content-type", "application/json") |> send_resp(200, input)
        end
      end
      """)

    assert [%{"line" => 8, "confidence" => "high"}] =
             scan("basic")
             |> findings_for("XSS.SendResp")
             |> Enum.filter(&String.ends_with?(&1["file"], path))
  end

  test "active and unknown MIME types report while JSON with another header stays clean" do
    path =
      temp_fixture_file("basic", "lib/media_responses.ex", """
      defmodule Response do
        alias Plug.Conn, as: PC
        def svg(conn, input), do: conn |> PC.put_resp_header("content-type", "image/svg+xml") |> PC.send_resp(200, input)
        def unknown(conn, input), do: conn |> PC.put_resp_header("content-type", "") |> PC.send_resp(200, input)
        def json(conn, input), do: conn |> PC.put_resp_header("content-type", "application/json") |> PC.put_resp_header("etag", "value") |> PC.send_resp(200, input)
      end
      """)

    results =
      scan("basic")
      |> findings_for("XSS.SendResp")
      |> Enum.filter(&String.ends_with?(&1["file"], path))

    assert [%{"line" => 3, "confidence" => "high"}, %{"line" => 4, "confidence" => "low"}] =
             results

    {sarif, _stderr} = scan_io("basic", format: "sarif")

    assert Enum.count(Jason.decode!(sarif)["runs"] |> hd() |> Map.fetch!("results"), fn result ->
             result["ruleId"] == "SBLW031"
           end) == 2
  end

  test "unsafe local raw wrappers preserve the original finding and both skip fingerprints" do
    source = """
    defmodule BasicWeb.RawController do
      use BasicWeb, :controller
      def unsafe(input), do: raw(input)
      def raw(input), do: {:safe, input}
    end
    """

    path = temp_fixture_file("basic", "lib/raw_controller.ex", source)

    assert [%{"line" => 3, "confidence" => "high"}] =
             scan("basic")
             |> findings_for("XSS.Raw")
             |> Enum.filter(&String.ends_with?(&1["file"], path))

    [actual] =
      Sobelow.FindingLog.log()
      |> Map.values()
      |> List.flatten()
      |> Enum.map(&elem(&1, 1))
      |> Enum.filter(&(&1.filename == path))

    fun =
      source
      |> Code.string_to_quoted!(columns: true)
      |> Sobelow.Lexical.functions()
      |> Map.keys()
      |> Enum.find(&(elem(Sobelow.Parse.get_fun_declaration(&1), 1) == {:unsafe, 3}))

    # The context-free public parser retains the pre-resolution call contract.
    [expected] =
      Sobelow.Finding.init("XSS.Raw: XSS", path)
      |> Sobelow.Finding.multi_from_def(fun, Sobelow.XSS.Raw.parse_raw_def(fun))
      |> Enum.map(&Sobelow.Finding.fetch_fingerprint/1)

    assert actual == expected

    temp_fixture_file("basic", ".sobelow-skips", "")
    scan_io("basic", mark_skip_all: true)
    assert findings(scan("basic", skip: true)) == []
  end
end
