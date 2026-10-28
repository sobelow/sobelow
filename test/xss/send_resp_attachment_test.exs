defmodule SobelowTest.XSS.SendRespAttachmentTest do
  use ExUnit.Case, async: true
  alias Sobelow.{Finding, Lexical}
  alias Sobelow.XSS.SendResp

  test "literal attachments suppress PDF and XML document findings in either setter order" do
    for type <- ["application/pdf", "application/xml", "text/xml", "application/example+xml"],
        disposition <- ["attachment", ~s| Attachment ; filename="report.pdf" |],
        setters <- [
          ~s'put_resp_content_type("#{type}") |> put_resp_header("content-disposition", #{inspect(disposition)})',
          ~s'put_resp_header("content-disposition", #{inspect(disposition)}) |> put_resp_content_type("#{type}")'
        ] do
      assert [] ==
               findings("def show(conn, input), do: conn |> #{setters} |> send_resp(200, input)")
    end
  end

  test "assigned aliases, nested setters and explicit imports retain attachment evidence" do
    for body <- [
          ~s|download = PC.put_resp_content_type(conn, "application/pdf")\ndownload = PC.put_resp_header(download, "content-disposition", "attachment")\nPC.send_resp(download, 200, input)|,
          ~s|PC.send_resp(PC.put_resp_header(PC.put_resp_content_type(conn, "application/pdf"), "content-disposition", "attachment"), 200, input)|,
          ~s'conn |> put_resp_content_type("application/pdf") |> put_resp_header("content-disposition", "attachment") |> put_resp_header("etag", "value") |> send_resp(200, input)'
        ] do
      assert [] ==
               findings("""
               defmodule Response do
                 alias Plug.Conn, as: PC
                 import PC, only: [put_resp_content_type: 2, put_resp_header: 3, send_resp: 3]
                 def show(conn, input) do
                   #{body}
                 end
               end
               """)
    end
  end

  test "an attachment never suppresses HTML, SVG or an unknown content type" do
    for type <- ["text/html", "image/svg+xml", "application/xhtml+xml", "", "application/unknown"] do
      assert [%Finding{}] =
               findings("""
               def show(conn, input) do
                 conn |> put_resp_content_type(#{inspect(type)})
                 |> put_resp_header("content-disposition", "attachment")
                 |> send_resp(200, input)
               end
               """)
    end

    assert [%Finding{}] =
             findings("""
             def show(conn, type, input) do
               conn |> put_resp_content_type(type)
               |> put_resp_header("content-disposition", "attachment")
               |> send_resp(200, input)
             end
             """)
  end

  test "inline, dynamic and malformed dispositions retain the document finding" do
    for value <- [
          ~s|"inline"|,
          "disposition",
          ~s|"attachment, inline"|,
          ~s|"attachment;"|,
          ~s|"attachment; filename"|,
          ~s|"attachment; filename=a; FILENAME=b"|,
          ~s|"attachment; filename=\\"unterminated"|,
          ~s|"attachment\\r\\ninline"|,
          ~s|"attachment; filename*=invalid"|
        ] do
      assert [%Finding{confidence: :low}] =
               findings("""
               def show(conn, disposition, input) do
                 conn |> put_resp_content_type("application/pdf")
                 |> put_resp_header("content-disposition", #{value})
                 |> send_resp(200, input)
               end
               """)
    end
  end

  test "the last disposition setter controls the response" do
    for value <- [~s|"inline"|, "disposition", ~s|"attachment, inline"|] do
      assert [%Finding{confidence: :low}] =
               findings("""
               def show(conn, disposition, input) do
                 conn |> put_resp_header("content-disposition", "attachment")
                 |> put_resp_header("content-disposition", #{value})
                 |> put_resp_content_type("application/pdf")
                 |> send_resp(200, input)
               end
               """)
    end

    assert [] ==
             findings("""
             def show(conn, input) do
               conn |> put_resp_header("content-disposition", "inline")
               |> put_resp_content_type("application/pdf")
               |> put_resp_header("content-disposition", "attachment")
               |> send_resp(200, input)
             end
             """)
  end

  test "discarded setters, other connections and setters after the sink cannot suppress findings" do
    for body <- [
          ~s|put_resp_header(conn, "content-disposition", "attachment")\nsend_resp(conn, 200, input)|,
          ~s|other = put_resp_header(other, "content-disposition", "attachment")\nsend_resp(conn, 200, input)|,
          ~s|send_resp(conn, 200, input)\nput_resp_header(conn, "content-disposition", "attachment")|
        ] do
      assert [%Finding{confidence: :low}] =
               findings("""
               def show(conn, other, input) do
                 conn = put_resp_content_type(conn, "application/pdf")
                 #{body}
               end
               """)
    end
  end

  test "unrecognized mutations and uncertain header keys invalidate attachment proof" do
    for operation <- [
          ~s|delete_resp_header("content-disposition")|,
          ~s|merge_resp_headers([{"content-disposition", "inline"}])|,
          ~s|prepend_resp_headers([{"content-disposition", "inline"}])|,
          ~s|put_resp_header(header, "inline")|,
          ~s|put_resp_header("Content-Disposition", "inline")|,
          ~s|put_resp_header("content-disposition")|,
          ~s|put_resp_content_type()|,
          ~s|unknown()|
        ] do
      assert [%Finding{}] =
               findings("""
               def show(conn, header, input) do
                 conn |> put_resp_content_type("application/pdf")
                 |> put_resp_header("content-disposition", "attachment")
                 |> #{operation}
                 |> send_resp(200, input)
               end
               """)
    end
  end

  test "unrelated imports and local helpers cannot prove an attachment" do
    for definition <- [
          "import CustomHeaders, only: [put_resp_header: 3]",
          "import CustomHeaders",
          "def put_resp_header(conn, _key, _value), do: conn",
          "defdelegate put_resp_header(conn, key, value), to: CustomHeaders"
        ] do
      assert [%Finding{}] =
               findings("""
               defmodule Response do
                 #{definition}
                 def show(conn, input) do
                   conn |> Plug.Conn.put_resp_content_type("application/pdf")
                   |> put_resp_header("content-disposition", "attachment")
                   |> Plug.Conn.send_resp(200, input)
                 end
               end
               """)
    end
  end

  test "attachment state cannot leak from an unselected branch" do
    assert [%Finding{confidence: :low}] =
             findings("""
             def show(conn, download?, input) do
               if download? do
                 conn = put_resp_content_type(conn, "application/pdf")
                 conn = put_resp_header(conn, "content-disposition", "attachment")
                 send_resp(conn, 200, input)
               else
                 conn |> put_resp_content_type("application/pdf") |> send_resp(200, input)
               end
             end
             """)
  end

  test "connection patterns shadow outer attachment evidence" do
    assert [%Finding{}] =
             findings("""
             def show(conn, conns, input) do
               conn = conn |> put_resp_content_type("application/pdf")
                           |> put_resp_header("content-disposition", "attachment")
               Enum.map(conns, fn conn -> send_resp(conn, 200, input) end)
             end
             """)
  end

  test "an unselected branch cannot prove a safe content type for another branch" do
    assert [%Finding{confidence: :high, vuln_line_no: 6}] =
             findings("""
             def show(conn, json?, input) do
               if json? do
                 conn = put_resp_content_type(conn, "application/json")
                 send_resp(conn, 200, input)
               else
                 send_resp(conn, 200, input)
               end
             end
             """)
  end

  test "proof established outside a conditional remains valid in both branches" do
    assert [] ==
             findings("""
             def show(conn, choice, input) do
               conn = conn |> put_resp_content_type("application/pdf")
                           |> put_resp_header("content-disposition", "attachment")
               if choice do
                 send_resp(conn, 200, input)
               else
                 send_resp(conn, 200, input)
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
