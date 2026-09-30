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

  for {scope, response} <- [
        {"anonymous function", "Enum.map(conns, fn conn -> send_resp(conn, 200, test) end)"},
        {"case pattern", "case load_connection() do\n conn -> send_resp(conn, 200, test)\nend"},
        {"with generator", "with conn <- load_connection(), do: send_resp(conn, 200, test)"},
        {"comprehension", "for conn <- conns, do: send_resp(conn, 200, test)"},
        {"tuple assignment", "{conn, _} = load_connection()\n send_resp(conn, 200, test)"},
        {"branch assignment",
         "if flag do\n conn = load_connection()\n send_resp(conn, 200, test)\nend"}
      ] do
    test "a #{scope} cannot inherit a content type from a different binding" do
      assert [%Finding{confidence: :high}] =
               findings("""
               def index(conn, conns, flag, %{"test" => test}) do
                 conn = Plug.Conn.put_resp_content_type(conn, "text/plain")
                 #{unquote(response)}
               end
               """)
    end
  end

  test "a content type set directly inside a branch still applies to its response" do
    assert [] ==
             findings("""
             def index(conn, flag, %{"test" => test}) do
               conn = Plug.Conn.put_resp_content_type(conn, "text/html")
               if flag do
                 conn |> Plug.Conn.put_resp_content_type("text/plain") |> send_resp(200, test)
               end
             end
             """)
  end

  test "branches and callbacks retaining the same connection retain its known content type" do
    for response <- [
          "if flag, do: send_resp(conn, 200, test)",
          "Enum.map(conns, fn other -> send_resp(conn, 200, test) end)",
          "Enum.map(conns, fn other when conn != nil -> send_resp(conn, 200, test) end)",
          "case flag do\n true -> send_resp(conn, 200, test)\nend",
          "case conn do\n ^conn -> send_resp(conn, 200, test)\nend",
          "with :ok <- check(), do: send_resp(conn, 200, test)",
          "cond do\n conn != nil -> send_resp(conn, 200, test)\nend"
        ] do
      assert [] ==
               findings("""
               def index(conn, conns, flag, %{"test" => test}) do
                 conn = Plug.Conn.put_resp_content_type(conn, "text/plain")
                 #{response}
               end
               """)
    end
  end

  test "a branch's own content type overrides the outer binding" do
    for {type, expected} <- [{"text/html", [:high]}, {"text/plain", []}] do
      results =
        findings("""
        def index(conn, flag, %{"test" => test}) do
          conn = Plug.Conn.put_resp_content_type(conn, "text/plain")
          if flag do
            conn = Plug.Conn.put_resp_content_type(conn, "#{type}")
            send_resp(conn, 200, test)
          end
        end
        """)

      assert Enum.map(results, & &1.confidence) == expected
    end
  end

  test "a binding changed inside a call argument affects the later response" do
    for {type, expected} <- [{"text/html", [:high]}, {"text/plain", []}] do
      results =
        findings("""
        def index(conn, %{"test" => test}) do
          conn = Plug.Conn.put_resp_content_type(conn, "text/plain")
          record(conn = Plug.Conn.put_resp_content_type(conn, "#{type}"))
          send_resp(conn, 200, test)
        end
        """)

      assert Enum.map(results, & &1.confidence) == expected
    end
  end

  defp findings(source) do
    ast = Code.string_to_quoted!(source)

    %Finding{}
    |> Finding.multi_from_def(ast, SendResp.parse_def(ast))
    |> Enum.map(&SendResp.set_confidence/1)
    |> Enum.reject(&SendResp.nil_confidence?/1)
  end
end
