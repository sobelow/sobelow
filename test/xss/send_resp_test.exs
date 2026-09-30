defmodule SobelowTest.XSS.SendRespTest do
  use ExUnit.Case
  alias Sobelow.XSS.SendResp
  alias Sobelow.Finding

  test "default content_type send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       send_resp(conn, 200, test)
    end
    """

    assert [%Finding{confidence: :high}] = findings(func)
  end

  test "vulnerable send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       put_resp_content_type(conn, "text/html")
       |> send_resp(200, test)
    end
    """

    assert [%Finding{confidence: :high}] = findings(func)
  end

  test "vulnerable aliased send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       put_resp_content_type(conn, "text/html")
       |> Plug.Conn.send_resp(200, test)
    end
    """

    assert [%Finding{confidence: :high}] = findings(func)
  end

  test "vulnerable alternative aliased send_resp" do
    func = """
    def index(conn, %{"test" => test}) do
       Plug.Conn.put_resp_content_type(conn, "text/html")
       |> Plug.Conn.send_resp(200, test)
    end
    """

    assert [%Finding{confidence: :high}] = findings(func)
  end

  test "safe send_resp due to content_type" do
    func = """
    def index(conn, %{"test" => test}) do
       Plug.Conn.put_resp_content_type(conn, "text/plain")
       |> send_resp(200, test)
    end
    """

    assert [] == findings(func)
  end

  test "safe send_resp" do
    func = """
    def index(conn, _params) do
      put_resp_content_type(conn, "text/html")
      |> send_resp(200, "body")
    end
    """

    assert [] == findings(func)
  end

  test "a later content type cannot suppress an earlier response" do
    assert [%Finding{confidence: :high}] =
             findings("""
             def index(conn, %{"test" => test}) do
               send_resp(conn, 200, test)
               Plug.Conn.put_resp_content_type(conn, "text/plain")
             end
             """)
  end

  test "an unpiped content type setter on the response connection is recognized" do
    assert [] ==
             findings("""
             def index(conn, %{"test" => test}) do
               conn = Plug.Conn.put_resp_content_type(conn, "text/plain")
               send_resp(conn, 200, test)
             end
             """)
  end

  test "a content type set on a different connection does not suppress a response" do
    assert [%Finding{confidence: :high}] =
             findings("""
             def index(conn, other, %{"test" => test}) do
               other = Plug.Conn.put_resp_content_type(other, "text/plain")
               send_resp(conn, 200, test)
             end
             """)
  end

  test "a directly nested content type setter is recognized" do
    assert [] ==
             findings("""
             def index(conn, %{"test" => test}) do
               send_resp(Plug.Conn.put_resp_content_type(conn, "text/plain"), 200, test)
             end
             """)
  end

  test "a content type setter whose return value is discarded cannot suppress a response" do
    assert [%Finding{confidence: :high}] =
             findings("""
             def index(conn, %{"test" => test}) do
               Plug.Conn.put_resp_content_type(conn, "text/plain")
               send_resp(conn, 200, test)
             end
             """)
  end

  defp findings(source) do
    ast = Code.string_to_quoted!(source)

    %Finding{}
    |> Finding.multi_from_def(ast, SendResp.parse_def(ast))
    |> Enum.map(&SendResp.set_confidence/1)
    |> Enum.reject(&SendResp.nil_confidence?/1)
  end
end
