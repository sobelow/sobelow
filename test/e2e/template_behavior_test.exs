defmodule Sobelow.TemplateBehaviorTest do
  use Sobelow.ScanCase, async: false

  test "a disable directive inside an attribute value cannot hide a template XSS finding" do
    path =
      temp_fixture_file("basic", "lib/basic_web/controllers/page_html/index.html.heex", """
      <div title=" phx-no-curly-interpolation ">{raw(@user_input)}</div>
      """)

    assert [%{"line" => 1}] =
             scan("basic")
             |> findings_for("XSS.Raw")
             |> Enum.filter(&String.ends_with?(&1["file"], path))
  end

  test "inline HEEx uses the aliases in scope at each sigil" do
    path =
      temp_fixture_file("basic", "lib/inline_aliases.ex", ~S'''
      defmodule InlineAliases do
        alias Phoenix.HTML, as: H
        def vulnerable(assigns), do: ~H"<span>{H.raw(@input)}</span>"
        def unrelated(assigns) do
          alias Other.HTML
          ~H"<span>{HTML.raw(@input)}</span>"
        end
        def outside(assigns), do: ~H"<span>{H.raw(@input)}</span>"
      end
      ''')

    assert scan("basic")
           |> findings_for("XSS.Raw")
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(& &1["line"]) == [3, 8]
  end

  test "comments and script text cannot hide a later template finding" do
    path =
      temp_fixture_file("basic", "lib/basic_web/controllers/page_html/adversarial.html.heex", """
      <!-- <div phx-no-curly-interpolation> -->
      <script>const html = "<span data={1 +}>";</script>
      <span>{raw(@input)}</span>
      <script><%= raw @script %></script>
      """)

    assert scan("basic")
           |> findings_for("XSS.Raw")
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(& &1["line"]) == [3, 4]
  end

  test "piped raw calls retain their template assigns for qualified and bare sinks" do
    path =
      temp_fixture_file("basic", "lib/basic_web/controllers/page_html/piped.html.heex", """
      <span>{@bare |> raw()}</span>
      <span>{@qualified |> Phoenix.HTML.raw()}</span>
      """)

    assert scan("basic")
           |> findings_for("XSS.Raw")
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(&{&1["line"], &1["variable"]}) == [{1, "@bare"}, {2, "@qualified"}]
  end

  test "inline HEEx detects raw pipes through renamed aliases" do
    path =
      temp_fixture_file("basic", "lib/inline_pipes.ex", ~S'''
      defmodule InlinePipes do
        alias Phoenix.HTML, as: H
        def render(assigns), do: ~H"<span>{@input |> H.raw()}</span>"
      end
      ''')

    assert [%{"line" => 3, "variable" => "@input"}] =
             scan("basic")
             |> findings_for("XSS.Raw")
             |> Enum.filter(&String.ends_with?(&1["file"], path))
  end

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
