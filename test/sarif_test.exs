defmodule SobelowTest.SarifTest do
  use Sobelow.CoverageCase, async: false

  alias Sobelow.RCE.CodeModule

  @metafile %{filename: "test.ex", controller?: true}

  setup do
    Application.put_env(:sobelow, :format, "sarif")

    :ok
  end

  test "Unique rule ids" do
    ids = Sobelow.rules() |> Enum.map(& &1.id)

    assert Enum.uniq(ids) |> length() == length(ids)
  end

  test "All finding modules have an id" do
    ids = Sobelow.finding_modules() |> Enum.map(&apply(&1, :id, []))

    assert Enum.uniq(ids) |> length() == length(ids)
  end

  test "All finding modules have docs" do
    assert Sobelow.finding_modules() |> Enum.map(&apply(&1, :details, [])) |> length() ==
             Sobelow.finding_modules() |> length()
  end

  test "all findings are registered for skips and listed in CLI help" do
    {:docs_v1, _, _, _, %{"en" => help}, _, _} = Code.fetch_docs(Mix.Tasks.Sobelow)

    for module <- Sobelow.finding_modules() do
      name = module |> Module.split() |> Enum.drop(1) |> Enum.join(".")

      assert Sobelow.get_mod(name) == module
      assert Sobelow.get_mod(module.rule().name) == module
      assert help =~ "* #{name}\n"
    end
  end

  test "All required fields available" do
    func = """
    def call(conn, _opts) do
      Code.eval_string(conn.body_params["code"])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    run_test = fn ->
      CodeModule.run(ast, @metafile)
    end

    run_test.()

    output = Jason.decode!(Sobelow.FindingLog.sarif("1"))
    run = List.first(output["runs"])
    results = run["results"]

    assert output["$schema"] ==
             "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

    assert output["version"] == "2.1.0"
    assert is_list(output["runs"])
    assert run["tool"]["driver"]["name"] == "Sobelow"
    assert is_list(run["results"])
    assert Enum.all?(results, &is_binary(&1["ruleId"]))
    assert Enum.all?(results, &is_binary(&1["message"]["text"]))
    assert Enum.all?(results, &is_list(&1["locations"]))

    assert Enum.all?(results, fn result ->
             Enum.all?(result["locations"], fn location ->
               region = location["physicalLocation"]["region"]

               is_binary(location["physicalLocation"]["artifactLocation"]["uri"]) &&
                 is_number(region["startLine"]) && is_number(region["startColumn"]) &&
                 is_number(region["endLine"]) && is_number(region["endColumn"])
             end)
           end)

    assert Enum.all?(results, &is_binary(&1["partialFingerprints"]["primaryLocationLineHash"]))
  end

  @tag :tmp_dir
  test "reserved filename characters remain part of a SARIF path", %{tmp_dir: tmp_dir} do
    Application.put_env(:sobelow, :root, tmp_dir)

    for filename <- ["hash#query?.ex", "percent%20.ex", "scheme:name.ex"] do
      path = Path.join(tmp_dir, filename)
      File.write!(path, "")

      finding =
        Sobelow.Finding.init("XSS.Raw: XSS", Sobelow.Utils.normalize_path(path), :low)
        |> Map.merge(%{vuln_source: :raw, vuln_line_no: 1, vuln_col_no: 1})
        |> Sobelow.Finding.fetch_fingerprint()

      Sobelow.FindingLog.add({%{}, finding, nil}, :low)
    end

    for result <- Sobelow.FindingLog.sarif_results() do
      uri = get_in(result, [:locations, Access.at(0), :physicalLocation, :artifactLocation, :uri])
      parsed = URI.parse(uri)
      assert parsed.scheme == nil
      assert parsed.query == nil
      assert parsed.fragment == nil
      assert URI.decode(parsed.path) in ["hash#query?.ex", "percent%20.ex", "scheme:name.ex"]
    end
  end

  @tag :tmp_dir
  test "an external source uses an absolute file URI", %{tmp_dir: tmp_dir} do
    root = Path.join(tmp_dir, "project")
    outside = Path.join(tmp_dir, "external.ex")
    File.mkdir_p!(root)
    File.write!(outside, "")

    previous_root = Application.get_env(:sobelow, :root)
    Application.put_env(:sobelow, :root, root)
    on_exit(fn -> Application.put_env(:sobelow, :root, previous_root) end)

    finding =
      Sobelow.Finding.init("XSS.Raw: XSS", Sobelow.Utils.normalize_path(outside), :low)
      |> Map.merge(%{vuln_source: :raw, vuln_line_no: 1, vuln_col_no: 1})
      |> Sobelow.Finding.fetch_fingerprint()

    Sobelow.FindingLog.add({%{}, finding, nil}, :low)

    assert [result] = Sobelow.FindingLog.sarif_results()

    assert get_in(result, [:locations, Access.at(0), :physicalLocation, :artifactLocation, :uri]) ==
             "file://" <> URI.encode(outside)
  end
end
