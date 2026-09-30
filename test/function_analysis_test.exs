defmodule Sobelow.FunctionAnalysisTest do
  use ExUnit.Case, async: false
  alias Sobelow.{FunctionAnalysis, Lexical, Parse}

  @sources [
    "def read(path), do: File.read(path)",
    "def read(path), do: path |> String.trim() |> File.read()",
    "def read(path), do: Enum.map(path, &File.read/1)",
    "def read(path), do: Enum.map(path, &File.read/unquote(length(path)))",
    "def read(path), do: path |> then(fn item -> File.read(item) end)",
    "def read(path) do\nif path, do: File.read(path), else: File.read!(path)\nend",
    ~S|def read(path \\ File.read("default")), do: File.read(path)|,
    "def read(path), do: :erlang.binary_to_atom(path)",
    "def read(path), do: Enum.map(path, &:erlang.binary_to_atom/1)",
    "def read(path), do: read(read(path))"
  ]

  test "shared analysis preserves helper results including captures, pipes and declarations" do
    for source <- @sources do
      ast = Code.string_to_quoted!(source, columns: true)
      expected = results(ast)
      assert FunctionAnalysis.with_fun(ast, fn -> results(ast) end) == expected
    end
  end

  test "analysis retains lexical alias and imported arity decisions" do
    ast =
      Code.string_to_quoted!(
        """
        defmodule Example do
          alias File, as: FS
          import Ecto.Adapters.SQL, only: [query: 3]
          def read(path), do: path |> FS.read()
          def sql(repo, value), do: query(repo, value, [])
        end
        """,
        columns: true
      )

    for {fun, context} <- Lexical.functions(ast) do
      Lexical.with_context(context, fn ->
        expected = results(fun)
        assert FunctionAnalysis.with_fun(fun, fn -> results(fun) end) == expected
      end)
    end
  end

  test "nested contexts and exceptions restore analysis" do
    first = Code.string_to_quoted!("def first(path), do: File.read(path)")
    second = Code.string_to_quoted!("def second(path), do: File.read!(path)")

    FunctionAnalysis.with_fun(first, fn ->
      before = results(first)

      assert_raise RuntimeError, fn ->
        FunctionAnalysis.with_fun(second, fn -> raise "stop" end)
      end

      assert results(first) == before
    end)

    assert results(second) == FunctionAnalysis.with_fun(second, fn -> results(second) end)
  end

  test "confidence follows the same prefixes across reassignment, branches and captures" do
    fun =
      Code.string_to_quoted!(
        """
        def read(path) do
          local = path
          File.read(local)
          local = unrelated()
          File.read(local)
          if path, do: File.read(path)
          Enum.map(path, &File.read/1)
          after_sink = path
        end
        """,
        columns: true
      )

    collect = fn ->
      Sobelow.Finding.init("Traversal.FileModule: test", "file.ex")
      |> Sobelow.Finding.multi_from_def(fun, Parse.get_fun_vars_and_meta(fun, 0, :read, [:File]))
    end

    expected = collect.()
    assert FunctionAnalysis.with_fun(fun, collect) == expected
  end

  test "existing source fixtures retain sink selection and full finding structs" do
    targets = [
      {:read, 0, [:File]},
      {:cp, 1, [:File]},
      {:query, 1, :SQL},
      {:query, 0, :Repo},
      {:send_resp, 2, :Conn},
      {:send_file, 2, :Conn},
      {:send_download, 1, :Controller},
      {:eval_string, 0, [:Code]},
      {:to_atom, 0, [:String]},
      {:raw, 0, :HTML}
    ]

    functions =
      Path.wildcard("test/fixtures/**/*.ex")
      |> Enum.flat_map(fn path ->
        ast = path |> File.read!() |> Code.string_to_quoted!(columns: true)
        Map.to_list(Lexical.functions(ast))
      end)

    assert functions != []

    for {fun, context} <- functions, {type, index, module} <- targets do
      Lexical.with_context(context, fn ->
        collect = fn ->
          parsed = Parse.get_fun_vars_and_meta(fun, index, type, module)
          finding = Sobelow.Finding.init("Compatibility: sink", "fixture.ex")
          {parsed, Sobelow.Finding.multi_from_def(finding, fun, parsed)}
        end

        expected = collect.()
        assert FunctionAnalysis.with_fun(fun, collect) == expected
      end)
    end
  end

  defp results(ast) do
    for type <- [:read, :read!, :query, :|>, :binary_to_atom], module <- [nil, [:File], :SQL] do
      {Parse.get_fun_vars_and_meta(ast, 0, type, module), Parse.get_funs_of_type(ast, type),
       Parse.get_aliased_funs_of_type(ast, type, [:File]),
       Parse.get_erlang_funs_of_type(ast, type), Parse.get_pipe_funs(ast),
       Parse.get_erlang_fun_vars_and_meta(ast, 0, type, :erlang)}
    end
  end
end
