defmodule Sobelow.GithubAnnotationsTest do
  use Sobelow.CoverageCase, async: false

  setup do
    workspace = System.get_env("GITHUB_WORKSPACE")
    System.delete_env("GITHUB_WORKSPACE")

    on_exit(fn ->
      if workspace,
        do: System.put_env("GITHUB_WORKSPACE", workspace),
        else: System.delete_env("GITHUB_WORKSPACE")
    end)

    :ok
  end

  defp add(overrides) do
    finding =
      struct!(
        Finding,
        Keyword.merge(
          [
            type: "Traversal.SendFile: Directory Traversal in `send_file`",
            confidence: :high,
            filename: "lib/controller.ex",
            vuln_line_no: 3,
            vuln_col_no: 7,
            fingerprint: "test"
          ],
          overrides
        )
      )

    FindingLog.add({[], finding, nil}, finding.confidence)
  end

  test "escapes properties and messages without injecting additional commands" do
    add(filename: "lib/a%,:\r\n_controller.ex", type: "Review: %\r\n::error::unexpected")

    assert FindingLog.github() ==
             "::warning file=lib/a%25%2C%3A%0D%0A_controller.ex,line=3,endLine=3,col=7::" <>
               "Sobelow: Review: %25%0D%0A::error::unexpected (high confidence)"
  end

  test "unknown locations use positive defaults and absent filenames are omitted" do
    for value <- [nil, 0, -1, "3"] do
      reset_logs()
      add(filename: nil, vuln_line_no: value, vuln_col_no: value)

      assert FindingLog.github() ==
               "::warning line=1,endLine=1,col=1::" <>
                 "Sobelow: Traversal.SendFile: Directory Traversal in `send_file` (high confidence)"
    end
  end

  test "empty reports have no output" do
    assert FindingLog.github() == nil
  end

  test "findings are ordered by location across confidence levels" do
    add(filename: "lib/z.ex", confidence: :high)
    add(filename: "lib/a.ex", confidence: :low)
    [first, second] = FindingLog.github() |> String.split("\n")

    assert first =~ "file=lib/a.ex"
    assert first =~ "(low confidence)"
    assert second =~ "file=lib/z.ex"
    assert second =~ "(high confidence)"
  end

  test "rendering preserves original sources, filenames and both fingerprints" do
    Application.put_env(:sobelow, :format, "github")
    finding = Finding.init("XSS.Raw: XSS", "lib/page.ex", :medium)
    source = quoted("def show(body), do: raw(body)")
    finding = %{finding | fun_source: source, vuln_source: source, vuln_line_no: 4}
    Print.add_finding(finding)
    original = FindingLog.log()

    assert FindingLog.github() =~ "file=lib/page.ex,line=4"
    assert FindingLog.log() == original

    assert [%Finding{fun_source: ^source, fingerprint: hash, legacy_fingerprint: legacy}] =
             logged_findings()

    assert hash == Finding.fingerprint(finding)
    assert legacy == Finding.legacy_fingerprint(finding)
  end

  test "empty workspace uses paths relative to the current directory" do
    System.put_env("GITHUB_WORKSPACE", "")
    add(filename: Path.expand("lib/controller.ex"))
    assert FindingLog.github() =~ "file=lib/controller.ex,"
  end

  test "files outside the workspace retain an absolute location" do
    workspace = Path.join(File.cwd!(), "nested")
    System.put_env("GITHUB_WORKSPACE", workspace)
    filename = Path.expand("lib/controller.ex")
    add(filename: filename)
    assert FindingLog.github() =~ "file=#{filename},"
  end

  test "a scan root is matched on complete path segments" do
    Application.put_env(:sobelow, :root, "app")
    add(filename: "application/lib/controller.ex")
    assert FindingLog.github() =~ "file=application/lib/controller.ex,"
  end
end
