defmodule Sobelow.DiagnosticsTest do
  use Sobelow.ScanCase, async: false

  test "a partial scan warns, keeps its findings and includes SARIF notifications" do
    temp_fixture_file("basic", "lib/broken.ex", "defmodule Broken do\n def nope(\n")
    {stdout, stderr} = scan_io("basic", format: "sarif", summary: true)
    run = Jason.decode!(stdout)["runs"] |> hd()
    assert run["results"] != []
    assert stderr =~ "broken.ex"
    assert stderr =~ "unparseable: 1"
    assert [invocation] = run["invocations"]
    assert invocation["executionSuccessful"] == true
    assert [notification] = invocation["toolExecutionNotifications"]
    assert notification["level"] == "warning"
    assert notification["message"]["text"] =~ "broken.ex"
  end

  test "summary is optional and does not add fields to JSON" do
    {stdout, stderr} = scan_io("basic", summary: true)
    assert stderr =~ "Scan summary:"

    assert Map.keys(Jason.decode!(stdout)) |> Enum.sort() == [
             "findings",
             "sobelow_version",
             "total_findings"
           ]

    {_stdout, stderr} = scan_io("basic")
    refute stderr =~ "Scan summary:"
  end

  test "ignored invalid files are counted without being parsed" do
    path = temp_fixture_file("basic", "lib/ignored.ex", "invalid (")
    {_stdout, stderr} = scan_io("basic", summary: true, ignored_files: [Path.expand(path)])
    assert stderr =~ "ignored: 1"
    assert stderr =~ "unparseable: 0"
  end

  test "invalid HEEx interpolation and inline EEx are included in partial scan diagnostics" do
    temp_fixture_file(
      "basic",
      "lib/basic_web/controllers/page_html/invalid.html.heex",
      "{raw(@name) + }"
    )

    temp_fixture_file("basic", "lib/invalid_inline.ex", ~s|defmodule Inline do
      def render(assigns), do: ~H"<%= if true do %>"
      def read(path), do: File.read(path)
    end|)
    {stdout, stderr} = scan_io("basic", summary: true)
    assert stderr =~ "invalid.html.heex"
    assert stderr =~ "invalid_inline.ex"
    assert stderr =~ "unparseable: 2"

    assert Enum.any?(
             Jason.decode!(stdout) |> findings_for("Traversal.FileModule"),
             &String.ends_with?(&1["file"], "invalid_inline.ex")
           )
  end

  test "unreadable project sources are reported once and remain nonfatal" do
    path = temp_fixture_file("basic", "lib/unreadable.ex", "defmodule Unreadable do\nend\n")
    File.chmod!(path, 0o000)
    on_exit(fn -> File.chmod(path, 0o600) end)
    {stdout, stderr} = scan_io("basic", summary: true)
    assert Jason.decode!(stdout)["total_findings"] > 0
    assert stderr =~ "unreadable: 1"
    assert length(Regex.scan(~r/Could not read .*unreadable.ex/, stderr)) == 1
  end
end
