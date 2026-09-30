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

  test "the content-type response header suppresses JSON responses (issue 45)" do
    assert [] ==
             findings("""
             def false_positive(conn, params) do
               conn
               |> put_resp_header("content-type", "application/json")
               |> send_resp(200, Jason.encode!(%{name: params["name"]}))
             end
             """)
  end

  test "header setters work through qualified pipes, assignments and nested calls" do
    for response <- [
          ~s'conn |> Plug.Conn.put_resp_header("content-type", "application/json") |> send_resp(200, test)',
          ~s'conn = Plug.Conn.put_resp_header(conn, "content-type", "text/plain")\nsend_resp(conn, 200, test)',
          ~s'send_resp(put_resp_header(conn, "content-type", "application/json; charset=utf-8"), 200, test)'
        ] do
      assert [] == findings("def index(conn, test) do\n#{response}\nend")
    end
  end

  test "HTML and dynamic content-type headers retain findings" do
    for {type, confidence} <- [{~s'"TEXT/HTML; charset=utf-8"', :high}, {"type", :low}] do
      assert [%Finding{confidence: ^confidence}] =
               findings("""
               def index(conn, type, test) do
                 conn |> put_resp_header("content-type", #{type}) |> send_resp(200, test)
               end
               """)
    end
  end

  test "only a content-type header on the connection before the sink can suppress a finding" do
    for response <- [
          ~s'send_resp(conn, 200, test)\nput_resp_header(conn, "content-type", "application/json")',
          ~s'put_resp_header(conn, "content-type", "application/json")\nsend_resp(conn, 200, test)',
          ~s'other = put_resp_header(other, "content-type", "application/json")\nsend_resp(conn, 200, test)',
          ~s'conn |> put_resp_header("accept", "application/json") |> send_resp(200, test)',
          ~s'conn |> put_resp_header("Content-Type", "application/json") |> send_resp(200, test)',
          ~s'conn |> put_resp_header(header, "application/json") |> send_resp(200, test)',
          ~s'conn |> put_req_header("content-type", "application/json") |> send_resp(200, test)',
          ~s'conn |> Other.Conn.put_resp_header("content-type", "application/json") |> send_resp(200, test)',
          ~s'conn |> put_resp_header("content-type", "application/json") |> unknown() |> send_resp(200, test)'
        ] do
      assert [%Finding{confidence: :high}] =
               findings("def index(conn, other, header, test) do\n#{response}\nend")
    end
  end

  test "the last content-type setter controls the response" do
    for setters <- [
          ~s'put_resp_header("content-type", "application/json") |> put_resp_header("content-type", "text/html")',
          ~s'put_resp_header("content-type", "application/json") |> put_resp_content_type("text/html")',
          ~s'put_resp_content_type("application/json") |> put_resp_header("content-type", "text/html")'
        ] do
      assert [%Finding{confidence: :high}] =
               findings("def index(conn, test), do: conn |> #{setters} |> send_resp(200, test)")
    end

    assert [] ==
             findings("""
             def index(conn, test) do
               conn
               |> put_resp_content_type("text/html")
               |> put_resp_header("content-type", "application/json")
               |> send_resp(200, test)
             end
             """)
  end

  test "piped content types with an explicit charset retain their media type" do
    assert [%Finding{confidence: :high}] =
             findings("""
             def index(conn, test) do
               conn |> put_resp_content_type("text/html", "utf-8") |> send_resp(200, test)
             end
             """)
  end

  test "a local header helper cannot claim to set the response content type" do
    for response <- [
          ~s'conn |> put_resp_header("content-type", "application/json") |> send_resp(200, test)',
          ~s'send_resp(put_resp_header(conn, "content-type", "application/json"), 200, test)'
        ] do
      ast =
        Code.string_to_quoted!("""
        defmodule Helpers do
          def index(conn, test), do: #{response}
          def put_resp_header(conn, _header, _value), do: conn
        end
        """)

      assert [%Finding{confidence: :high}] =
               Enum.flat_map(Sobelow.Lexical.functions(ast), fn {fun, context} ->
                 Sobelow.Lexical.with_context(context, fn -> findings_from_ast(fun) end)
               end)
    end
  end

  test "qualified headers and different local arities retain Plug's setter behavior" do
    for {helper, response} <- [
          {"def put_resp_header(conn, _header, _value), do: conn",
           ~s'conn |> Plug.Conn.put_resp_header("content-type", "application/json") |> send_resp(200, test)'},
          {"def put_resp_header(conn, _header), do: conn",
           ~s'conn |> put_resp_header("content-type", "application/json") |> send_resp(200, test)'}
        ] do
      ast =
        Code.string_to_quoted!("""
        defmodule Helpers do
          def index(conn, test), do: #{response}
          #{helper}
        end
        """)

      assert [] ==
               Enum.flat_map(Sobelow.Lexical.functions(ast), fn {fun, context} ->
                 Sobelow.Lexical.with_context(context, fn -> findings_from_ast(fun) end)
               end)
    end
  end

  defp findings(source) do
    ast = Code.string_to_quoted!(source)

    context = Map.fetch!(Sobelow.Lexical.functions(ast), ast)

    Sobelow.Lexical.with_context(context, fn ->
      findings_from_ast(ast)
    end)
  end

  defp findings_from_ast(ast) do
    %Finding{}
    |> Finding.multi_from_def(ast, SendResp.parse_def(ast))
    |> Enum.map(&SendResp.set_confidence/1)
    |> Enum.reject(&SendResp.nil_confidence?/1)
  end
end
