defmodule SobelowTest.PrintTest do
  use ExUnit.Case
  import ExUnit.CaptureIO
  alias Sobelow.RCE.CodeModule

  @metafile %{filename: "test.ex", controller?: true}

  setup do
    Application.put_env(:sobelow, :format, "txt")
    Application.put_env(:sobelow, :threshold, :low)
    Application.put_env(:sobelow, :skip, false)
    Sobelow.Fingerprint.start_link()

    :ok
  end

  test "Prints variables with map access" do
    func = """
    def call(conn, _opts) do
      Code.eval_string(conn.body_params["code"])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    run_test = fn ->
      Sobelow.FindingLog.start_link()

      CodeModule.run(ast, @metafile)

      # Findings are printed once the scan finishes rather than as they are
      # logged, so that a parallel scan still reports in a stable order.
      Sobelow.FindingLog.print_txt()
    end

    assert capture_io(run_test) =~ "Code Execution in `Code.eval_string` - Medium Confidence"
  end
end
