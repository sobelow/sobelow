defmodule Sobelow.TemplateBehaviorTest do
  use Sobelow.ScanCase, async: false

  for format <- ["json", "txt", "compact", "flycheck", "quiet"] do
    test "a local render assign retains medium confidence in #{format} output" do
      path =
        temp_fixture_file("basic", "lib/basic_web/controllers/template_controller.ex", """
        defmodule BasicWeb.TemplateController do
          use BasicWeb, :controller
          def show(conn, _params) do
            conn |> render("show.html", message: load_message())
          end
        end
        """)

      temp_fixture_file(
        "basic",
        "lib/basic_web/templates/template/show.html.eex",
        "<%= raw @message %>"
      )

      {stdout, _stderr} = scan_io("basic", format: unquote(format))
      findings = Sobelow.FindingLog.log().medium |> Enum.map(&elem(&1, 1))

      assert [%Sobelow.Finding{vuln_variable: "@message", vuln_line_no: 4}] =
               Enum.filter(findings, &String.ends_with?(&1.filename, path))

      assert stdout != ""
    end
  end

  test "dynamic template names remain nonfatal and medium thresholds retain high findings" do
    temp_fixture_file("basic", "lib/basic_web/controllers/dynamic_controller.ex", """
    defmodule BasicWeb.DynamicController do
      use BasicWeb, :controller
      def show(conn, params), do: render(conn, params["template"], message: load_message())
    end
    """)

    report = scan("basic", threshold: :medium)
    assert findings(report) != []
    refute Enum.any?(findings(report), &(&1["confidence"] == "low"))
  end

  test "ignoring the XSS category skips direct and template findings" do
    report = scan("basic", ignored: ["XSS"])
    refute Enum.any?(finding_modules(report), &String.starts_with?(&1, "XSS."))
    assert findings_for(report, "Traversal.SendFile") != []
  end

  @tag :tmp_dir
  test "nonprivate scans reuse a fresh version timestamp without contacting the service", %{
    tmp_dir: dir
  } do
    previous = System.get_env("SOBELOW_HOME")
    System.put_env("SOBELOW_HOME", dir)

    on_exit(fn ->
      if previous,
        do: System.put_env("SOBELOW_HOME", previous),
        else: System.delete_env("SOBELOW_HOME")
    end)

    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    File.write!(Sobelow.version_check_file(), "sobelow-#{timestamp}")
    {stdout, stderr} = scan_io("basic", private: false)
    assert Jason.decode!(stdout)["total_findings"] > 0
    refute stderr =~ "Checking Sobelow version"
  end
end
