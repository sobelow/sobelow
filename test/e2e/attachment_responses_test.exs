defmodule Sobelow.AttachmentResponsesTest do
  use Sobelow.ScanCase, async: false
  alias Sobelow.{Finding, FindingLog, Lexical}
  alias Sobelow.XSS.SendResp

  @source """
  defmodule BasicWeb.DownloadController do
    use BasicWeb, :controller
    def download(conn, input), do: conn |> put_resp_content_type("application/pdf") |> put_resp_header("content-disposition", "attachment; filename=\\"report.pdf\\"") |> send_resp(200, input)
    def inline(conn, input), do: conn |> put_resp_content_type("application/pdf") |> send_resp(200, input)
    def svg(conn, input), do: conn |> put_resp_content_type("image/svg+xml") |> put_resp_header("content-disposition", "attachment") |> send_resp(200, input)
    def uncertain(conn, disposition, input), do: conn |> put_resp_content_type("application/pdf") |> put_resp_header("content-disposition", disposition) |> send_resp(200, input)
  end
  """

  test "only the proven document download is suppressed, with stable remaining findings and skips" do
    path = temp_fixture_file("basic", "lib/basic_web/controllers/download_controller.ex", @source)

    assert [
             %{"line" => 4, "confidence" => "low"},
             %{"line" => 5, "confidence" => "high"},
             %{"line" => 6, "confidence" => "low"}
           ] =
             scan("basic", only: ["XSS.SendResp"])
             |> findings_for("XSS.SendResp")
             |> Enum.filter(&(&1["file"] == path))
             |> Enum.sort_by(& &1["line"])

    inline =
      FindingLog.log()
      |> Map.values()
      |> List.flatten()
      |> Enum.map(&elem(&1, 1))
      |> Enum.find(&(&1.filename == path and &1.fun_name == :inline))

    fun =
      @source
      |> Code.string_to_quoted!(columns: true)
      |> Lexical.functions()
      |> Map.keys()
      |> Enum.find(&(elem(Sobelow.Parse.get_fun_declaration(&1), 1) == {:inline, 4}))

    [expected] =
      Finding.init("XSS.SendResp: XSS in `send_resp`", path, :low)
      |> Finding.multi_from_def(fun, SendResp.parse_def(fun))
      |> Enum.map(&Finding.fetch_fingerprint/1)

    assert inline == expected

    {sarif, _stderr} = scan_io("basic", only: ["XSS.SendResp"], format: "sarif")
    [run] = Jason.decode!(sarif)["runs"]
    assert length(run["results"]) == 3
    assert Enum.all?(run["results"], &(&1["ruleId"] == "SBLW031"))

    temp_fixture_file("basic", ".sobelow-skips", "")
    scan_io("basic", only: ["XSS.SendResp"], mark_skip_all: true)
    assert [] == scan("basic", only: ["XSS.SendResp"], skip: true) |> findings()
  end

  test "the download decision is consistent across every output format" do
    path = temp_fixture_file("basic", "lib/basic_web/controllers/download_controller.ex", @source)

    fingerprints =
      for format <- ["txt", "compact", "flycheck", "json", "sarif", "github", "quiet"] do
        scan_io("basic", only: ["XSS.SendResp"], format: format)

        found =
          FindingLog.log()
          |> Map.values()
          |> List.flatten()
          |> Enum.map(&elem(&1, 1))
          |> Enum.filter(&(&1.filename == path))

        assert Enum.sort(Enum.map(found, & &1.vuln_line_no)) == [4, 5, 6]
        found |> Enum.map(& &1.fingerprint) |> Enum.sort()
      end

    assert length(Enum.uniq(fingerprints)) == 1
  end
end
