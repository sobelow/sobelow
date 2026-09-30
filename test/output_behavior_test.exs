defmodule Sobelow.OutputBehaviorTest do
  use Sobelow.CoverageCase, async: false

  test "confidence grading handles parameter lists, connection params and pinned confidence" do
    assert Print.get_sev([:input], :input) == :medium
    assert Print.get_sev([:input], :other) == :low
    assert Print.get_sev([], "conn.params") == :medium
    assert Print.get_sev([:input], :input, false) == :high
    assert Print.get_sev([], :other, false) == :medium
    assert Print.get_sev([:input], [:other, :input], nil) == :high
    assert Print.get_sev([], [:one, :two], nil) == :medium
    assert Print.get_sev([], [], nil) == :low
    assert Print.get_sev([:input], :input, :low) == :low
  end

  test "flycheck preserves location and respects thresholds and skip fingerprints" do
    Application.put_env(:sobelow, :format, "flycheck")
    finding = Finding.init("XSS.Raw: XSS", "page.ex", :medium)
    finding = %{finding | vuln_line_no: 7, vuln_source: :raw}
    assert capture_io(fn -> Print.add_finding(finding) end) == "page.ex:7: XSS.Raw: XSS\n"
    assert [%Finding{type: "page.ex:7: XSS.Raw: XSS"}] = logged_findings()

    Application.put_env(:sobelow, :threshold, :high)
    assert capture_io(fn -> Print.add_finding(finding) end) == ""

    Application.put_env(:sobelow, :threshold, :low)
    Application.put_env(:sobelow, :skip, true)
    Sobelow.Fingerprint.put_ignore(Finding.fingerprint(finding))
    assert capture_io(fn -> Print.add_finding(finding) end) == ""
    assert FindingLog.counts() == %{high: 0, medium: 1, low: 0}
  end

  test "verbose rendering highlights the original sink and normalizes template assigns" do
    ast = quoted("def read(path), do: File.read(path)")
    [sink] = Parse.get_funs_by_module(ast, [:File])
    output = capture_io(fn -> Print.print_code(ast, sink) end)
    assert output =~ IO.ANSI.light_magenta() <> "File.read(path)" <> IO.ANSI.reset()
    assert output =~ "def read(path)"

    template = EEx.compile_string("<%= raw @body %>")
    output = capture_io(fn -> Print.print_code(template, :absent) end)
    assert output =~ "@body"
    refute output =~ "EEx.Engine.fetch_assign!"
  end

  test "verbose rendering supports custom text, whole expressions and absent sources" do
    assert capture_io(fn -> Print.print_code(nil, nil) end) == ""
    assert capture_io(fn -> Print.print_code(nil, "explanation") end) =~ "explanation"

    assert capture_io(fn -> Print.print_code(quoted("socket()"), :highlight_all) end) =~
             IO.ANSI.light_magenta() <> "socket()"

    Application.put_env(:sobelow, :verbose, true)

    assert capture_io(fn -> Print.maybe_print_code(quoted("read(path)"), :absent) end) =~
             "read(path)"
  end

  test "metadata supports AST locations, map access and unquoted function names" do
    assert Print.finding_line(quoted("read(path)")) == "Line: 1"
    assert Print.finding_variable(quoted("conn.params")) == "Variable: conn.params()"

    assert capture_io(fn -> Print.print_finding_fun_metadata(quoted("unquote(name)"), 3) end) ==
             "Function: unquote(name):3\n"

    assert Print.maybe_print_finding_fun_metadata("", 3) == nil
  end

  test "JSON recursively normalizes AST values and SARIF supports unknown rules" do
    value = %{one: [quoted("conn.params"), %{two: 2}]}
    assert FindingLog.format_json(value) == %{one: ["\"conn.params()\"", %{two: 2}]}
    Application.put_env(:sobelow, :root, "")

    for type <- ["Unknown.Rule: custom", "XSS: category"] do
      finding = Finding.init(type, "page.ex", :low)
      finding = %{finding | vuln_line_no: 0, vuln_col_no: 0, fingerprint: "fingerprint"}
      FindingLog.add({%{}, finding, nil}, :low)
    end

    results = FindingLog.sarif_results()
    assert length(results) == 2
    assert Enum.all?(results, &is_nil(&1.ruleId))

    assert Enum.all?(results, fn result ->
             location = hd(result.locations).physicalLocation
             location.artifactLocation.uri == "page.ex" and location.region.startLine == 1
           end)
  end

  test "quiet output distinguishes zero, one and multiple findings" do
    assert FindingLog.quiet() == nil
    finding = Finding.init("XSS.Raw: XSS", "page.ex", :low)
    FindingLog.add({%{}, finding, nil}, :low)
    assert FindingLog.quiet() =~ "1 finding found."
    FindingLog.add({%{}, finding, nil}, :low)
    assert FindingLog.quiet() =~ "2 findings found."
  end

  test "IO helpers handle confirmation, rejection, EOF and error messages" do
    for input <- ["\n", "y\n", "YES\n"] do
      assert capture_io(input, fn -> assert Sobelow.IO.yes?("Continue?") end) =~ "[Yn]"
    end

    for input <- ["n\n", "unexpected\n", ""] do
      capture_io(input, fn -> refute Sobelow.IO.yes?("Continue?") end)
    end

    assert capture_io(:stderr, fn -> Sobelow.IO.error("failure") end) =~ "failure"
  end
end
