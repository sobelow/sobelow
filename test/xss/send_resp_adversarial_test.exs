defmodule SobelowTest.XSS.SendRespAdversarialTest do
  use ExUnit.Case, async: true
  alias Sobelow.{Finding, Lexical}
  alias Sobelow.XSS.SendResp

  test "explicit imports of unrelated setters cannot suppress a response" do
    for {setter, arguments} <- [
          {:put_resp_header, ~s'"content-type", "application/json"'},
          {:put_resp_content_type, ~s'"application/json"'}
        ] do
      arity = if setter == :put_resp_header, do: 3, else: 2

      assert [%Finding{confidence: :high}] =
               findings("""
               defmodule Controller do
                 import CustomHeaders, only: [#{setter}: #{arity}]
                 def index(conn, input), do: conn |> #{setter}(#{arguments}) |> send_resp(200, input)
               end
               """)
    end
  end

  test "unknown imports cannot supply evidence of a safe content-type setter" do
    for import <- [
          "import CustomHeaders",
          "import CustomHeaders, only: @setters",
          "import CustomHeaders, only: :macros"
        ] do
      assert [%Finding{confidence: :high}] =
               findings("""
               defmodule Controller do
                 #{import}
                 def index(conn, input) do
                   conn |> put_resp_header("content-type", "application/json") |> send_resp(200, input)
                 end
               end
               """)
    end
  end

  test "local macros and delegates cannot supply evidence of a safe setter" do
    for definition <- [
          "defmacro put_resp_header(conn, _header, _value), do: conn",
          "defmacrop put_resp_header(conn, _header, _value), do: conn",
          "defdelegate put_resp_header(conn, header, value), to: CustomHeaders",
          "def put_resp_content_type(conn, _type), do: conn"
        ] do
      setter =
        if String.contains?(definition, "put_resp_header"),
          do: ~s'put_resp_header("content-type", "application/json")',
          else: ~s'put_resp_content_type("application/json")'

      assert [%Finding{confidence: :high}] =
               findings("""
               defmodule Controller do
                 #{definition}
                 def index(conn, input), do: conn |> #{setter} |> send_resp(200, input)
               end
               """)
    end
  end

  test "known Plug imports retain safe responses with unrelated imports" do
    assert [] ==
             findings("""
             defmodule Controller do
               alias Plug.Conn, as: PC
               import PC, only: [put_resp_header: 3]
               import CustomHeaders, except: [put_resp_header: 3]
               def index(conn, input) do
                 conn |> put_resp_header("content-type", "application/json") |> send_resp(200, input)
               end
             end
             """)
  end

  test "SVG response content cannot be treated as safe non-HTML data" do
    for type <- ["image/svg+xml", "IMAGE/SVG+XML; charset=utf-8"],
        setter <- [
          ~s'put_resp_header("content-type", "#{type}")',
          ~s'put_resp_content_type("#{type}")'
        ] do
      assert [%Finding{confidence: :high}] =
               findings("def index(conn, input), do: conn |> #{setter} |> send_resp(200, input)")
    end
  end

  test "empty or malformed content types cannot prove a response safe" do
    for type <- [
          "",
          " ",
          "unknown",
          "application",
          "/json",
          "text/",
          "application/json, text/html"
        ] do
      assert [%Finding{}] =
               findings("""
               def index(conn, input) do
                 conn |> put_resp_header("content-type", #{inspect(type)}) |> send_resp(200, input)
               end
               """)
    end
  end

  test "known unrelated response headers preserve a JSON content type" do
    for response <- [
          ~s'conn |> put_resp_header("content-type", "application/json") |> put_resp_header("etag", "value") |> send_resp(200, input)',
          ~s'conn = put_resp_header(conn, "content-type", "application/json")\nconn = Plug.Conn.put_resp_header(conn, "cache-control", "no-cache")\nsend_resp(conn, 200, input)',
          ~s'conn = put_resp_header(conn, "content-type", "application/json")\nsend_resp(put_resp_header(conn, "etag", "value"), 200, input)'
        ] do
      assert [] == findings("def index(conn, input) do\n#{response}\nend")
    end
  end

  test "dynamic or differently cased content-type headers invalidate a known type" do
    for key <- ["header", ~s'"Content-Type"'] do
      assert [%Finding{confidence: :high}] =
               findings("""
               def index(conn, header, input) do
                 conn
                 |> put_resp_header("content-type", "application/json")
                 |> put_resp_header(#{key}, "text/html")
                 |> send_resp(200, input)
               end
               """)
    end
  end

  test "an unrelated header cannot erase an HTML content type" do
    assert [%Finding{confidence: :high}] =
             findings("""
             def index(conn, input) do
               conn
               |> put_resp_header("content-type", "text/html")
               |> put_resp_header("etag", "value")
               |> send_resp(200, input)
             end
             """)
  end

  test "browser sniffing placeholders cannot prove a response safe" do
    for type <- ["application/unknown", "unknown/unknown", "*/*"] do
      assert [%Finding{confidence: :low}] =
               findings("""
               def index(conn, input) do
                 conn |> put_resp_header("content-type", #{inspect(type)}) |> send_resp(200, input)
               end
               """)
    end
  end

  test "other scriptable document types retain low-confidence findings" do
    for type <- ["application/xml", "text/xml", "application/example+xml", "application/pdf"] do
      assert [%Finding{confidence: :low}] =
               findings("""
               def index(conn, input) do
                 conn |> put_resp_header("content-type", #{inspect(type)}) |> send_resp(200, input)
               end
               """)
    end
  end

  test "MIME parameters do not change the parsed media type" do
    for type <- [
          "application/json; description=html",
          "TEXT/PLAIN; name=html",
          "application/problem+json"
        ] do
      assert [] ==
               findings("""
               def index(conn, input) do
                 conn |> put_resp_header("content-type", #{inspect(type)}) |> send_resp(200, input)
               end
               """)
    end
  end

  test "non-ASCII whitespace and case folding cannot turn an invalid MIME type into a safe one" do
    for type <- ["\u00a0application/json", "application/json\u00a0", "application/\u212ajson"] do
      assert [%Finding{confidence: :low}] =
               findings("""
               def index(conn, input) do
                 conn |> put_resp_header("content-type", #{inspect(type)}) |> send_resp(200, input)
               end
               """)
    end
  end

  test "a function-local import cannot affect the setter in another function" do
    assert [%Finding{fun_name: :custom, confidence: :high}] =
             findings("""
             defmodule Controller do
               use MyAppWeb, :controller
               def custom(conn, input) do
                 import CustomHeaders, only: [put_resp_header: 3]
                 conn |> put_resp_header("content-type", "application/json") |> send_resp(200, input)
               end
               def json(conn, input) do
                 conn |> put_resp_header("content-type", "application/json") |> send_resp(200, input)
               end
             end
             """)
  end

  defp findings(source) do
    source
    |> Code.string_to_quoted!(columns: true)
    |> Lexical.functions()
    |> Enum.flat_map(fn {fun, context} ->
      Lexical.with_context(context, fn ->
        %Finding{}
        |> Finding.multi_from_def(fun, SendResp.parse_def(fun))
        |> Enum.map(&SendResp.set_confidence/1)
        |> Enum.reject(&SendResp.nil_confidence?/1)
      end)
    end)
  end
end
