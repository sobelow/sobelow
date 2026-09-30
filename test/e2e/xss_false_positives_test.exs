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
end
