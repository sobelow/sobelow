defmodule SobelowTest.FormatTest do
  use Sobelow.CoverageCase, async: false
  alias Sobelow.RCE.CodeModule

  @metafile %{filename: "test.ex", controller?: true}

  test "Formats variables with map access" do
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

    assert Sobelow.FindingLog.json("1") =~ "RCE.CodeModule: Code Execution in `Code.eval_string`"
  end
end
