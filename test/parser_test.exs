defmodule SobelowTest.ParserTest do
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

  test "Parser handles unquoted capture funcs" do
    func = """
    def call(list) do
      Enum.map(list, &Code.eval_string/unquote(length(list)))
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    run_test = fn ->
      Sobelow.FindingLog.start_link()

      CodeModule.run(ast, @metafile)

      # Wait for FindingLog GenServer to process the message and emit the log output
      Sobelow.FindingLog.log()
    end

    assert capture_io(run_test) =~ "Code Execution in `Code.eval_string` - Medium Confidence"
  end

  describe "get_pipelines_with_skips/1" do
    setup do
      Application.put_env(:sobelow, :skip, true)
      on_exit(fn -> Application.put_env(:sobelow, :skip, false) end)
    end

    defp pipeline_names(source) do
      {:ok, ast} = Code.string_to_quoted(source)

      ast
      |> Sobelow.Parse.get_pipelines_with_skips()
      |> Enum.map(fn {{:pipeline, _, [name | _]}, skips} -> {name, skips} end)
    end

    test "collects pipelines in source order" do
      source = """
      defmodule R do
        use W, :router

        pipeline :browser do
          plug(:accepts, ["html"])
        end

        pipeline :api do
          plug(:accepts, ["json"])
        end
      end
      """

      assert [browser: [], api: []] = pipeline_names(source)
    end

    test "collects a pipeline that is a module's only expression" do
      source = """
      defmodule R do
        pipeline :browser do
          plug(:accepts, ["html"])
        end
      end
      """

      assert [browser: []] = pipeline_names(source)
    end

    # A pipeline is scanned wherever it appears. Associating skips only works for
    # pipelines in a plain block, but a nested one must still be reported rather
    # than silently dropped.
    test "collects a pipeline nested outside a plain block" do
      source = """
      defmodule R do
        use W, :router

        if Mix.env() == :dev do
          pipeline :dev_only do
            plug(:accepts, ["html"])
          end
        end

        pipeline :browser do
          plug(:accepts, ["html"])
        end
      end
      """

      names = pipeline_names(source)

      assert {:dev_only, []} in names
      assert {:browser, []} in names
    end

    test "associates a skip with the pipeline that follows it" do
      source = """
      defmodule R do
        use W, :router

        @sobelow_skip ["Config.CSRF"]
        pipeline :browser do
          plug(:accepts, ["html"])
        end

        pipeline :api do
          plug(:accepts, ["json"])
        end
      end
      """

      assert [browser: ["Config.CSRF"], api: []] = pipeline_names(source)
    end

    test "does not associate a skip separated from the pipeline by another statement" do
      source = """
      defmodule R do
        @sobelow_skip ["Config.CSRF"]
        use W, :router

        pipeline :browser do
          plug(:accepts, ["html"])
        end
      end
      """

      assert [browser: []] = pipeline_names(source)
    end

    test "returns no skips when the skip flag is disabled" do
      Application.put_env(:sobelow, :skip, false)

      source = """
      defmodule R do
        @sobelow_skip ["Config.CSRF"]
        pipeline :browser do
          plug(:accepts, ["html"])
        end
      end
      """

      assert [browser: []] = pipeline_names(source)
    end
  end

  # `get_meta_funs/1` drops the `@sobelow_skip` attributes that a pipeline has
  # already consumed, so `Sobelow.combine_skips/2` cannot also bind them to the
  # next function. A correctly placed function-level skip can never be consumed:
  # the statement directly after the attribute is either a `pipeline` or a `def`,
  # and only the former consumes it.
  describe "get_meta_funs/1 and pipeline skips" do
    setup do
      Application.put_env(:sobelow, :skip, true)
      on_exit(fn -> Application.put_env(:sobelow, :skip, false) end)
    end

    defp def_fun_summary(source) do
      {:ok, ast} = Code.string_to_quoted(source)

      ast
      |> Sobelow.Parse.get_meta_funs()
      |> Map.fetch!(:def_funs)
      |> Enum.map(fn
        {:@, _, [{:sobelow_skip, _, [skips]}]} -> {:skip_attr, skips}
        {kind, _, [{name, _, _} | _]} -> {kind, name}
      end)
    end

    test "a skip consumed by a pipeline is not left for the next function" do
      source = """
      defmodule R do
        use W, :router

        @sobelow_skip ["Traversal.SendFile"]
        pipeline :browser do
          plug(:accepts, ["html"])
        end

        def download(conn, params) do
          send_file(conn, 200, params["path"])
        end
      end
      """

      assert [def: :download] = def_fun_summary(source)
    end

    test "a function-level skip is preserved in a router that also skips a pipeline" do
      source = """
      defmodule R do
        use W, :router

        @sobelow_skip ["Config.CSRF"]
        pipeline :browser do
          plug(:accepts, ["html"])
        end

        @sobelow_skip ["Traversal.SendFile"]
        def download(conn, params) do
          send_file(conn, 200, params["path"])
        end
      end
      """

      assert [def: :download, skip_attr: ["Traversal.SendFile"]] = def_fun_summary(source)
    end

    test "a plain function-level skip is untouched" do
      source = """
      defmodule M do
        @sobelow_skip ["Traversal.SendFile"]
        def download(conn, params) do
          send_file(conn, 200, params["path"])
        end
      end
      """

      assert [def: :download, skip_attr: ["Traversal.SendFile"]] = def_fun_summary(source)
    end

    test "a `pipeline` call in a non-router module still consumes an adjacent skip" do
      # Not a Phoenix router, but the association is purely syntactic. The skip
      # binds to the `pipeline` call, so it must not reach `handle/1`. This is
      # the safe direction: a lost skip surfaces a finding rather than hiding one.
      source = """
      defmodule M do
        @sobelow_skip ["Traversal.SendFile"]
        pipeline :something

        def handle(conn, params) do
          send_file(conn, 200, params["path"])
        end
      end
      """

      assert [def: :handle] = def_fun_summary(source)
    end
  end
end
