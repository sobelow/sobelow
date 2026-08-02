defmodule SobelowTest.SQL.QueryTest do
  use ExUnit.Case
  import Sobelow, only: [vuln?: 1]
  alias Sobelow.SQL.Query

  @query_funcs [:query, :query!]

  test "SQL injection in `SQL`" do
    Enum.each(@query_funcs, fn query_func ->
      func = """
      def query(%{"sql" => sql}) do
        SQL.#{query_func}(Repo, sql, [])
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      assert Query.parse_sql_def(ast, query_func) |> vuln?
    end)
  end

  test "Safe `SQL`" do
    Enum.each(@query_funcs, fn query_func ->
      func = """
      def query(%{"sql" => sql}) do
        SQL.#{query_func}(Repo, "SELECT * FROM users", [])
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      refute Query.parse_sql_def(ast, query_func) |> vuln?
    end)
  end

  test "SQL injection in `Repo`" do
    Enum.each(@query_funcs, fn query_func ->
      func = """
      def query(%{"sql" => sql}) do
        Repo.#{query_func}(sql)
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      assert Query.parse_repo_query_def(ast, query_func) |> vuln?
    end)
  end

  test "safe `Repo`" do
    Enum.each(@query_funcs, fn query_func ->
      func = """
      def query(%{"sql" => sql}) do
        Repo.#{query_func}("SELECT * FROM users")
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      refute Query.parse_repo_query_def(ast, query_func) |> vuln?
    end)
  end

  # `query` and `query!` are ordinary function names. Matching them unqualified
  # flags every local function that happens to be called one, so the unqualified
  # form is only considered for a file that imported `Ecto.Adapters.SQL` or is
  # itself an `Ecto.Repo`. See https://github.com/sobelow/sobelow/issues/30.
  describe "unqualified calls" do
    test "are not matched by default" do
      Enum.each(@query_funcs, fn query_func ->
        func = """
        def caller(%{"sql" => sql}) do
          #{query_func}(sql)
        end
        """

        {_, ast} = Code.string_to_quoted(func)

        refute Query.parse_repo_query_def(ast, query_func) |> vuln?
        refute Query.parse_sql_def(ast, query_func) |> vuln?
      end)
    end

    test "are matched when the file is an `Ecto.Repo`" do
      Enum.each(@query_funcs, fn query_func ->
        func = """
        def caller(%{"sql" => sql}) do
          #{query_func}(sql)
        end
        """

        {_, ast} = Code.string_to_quoted(func)

        assert Query.parse_repo_query_def(ast, query_func, true) |> vuln?
      end)
    end

    test "are matched when the file imported `Ecto.Adapters.SQL`" do
      Enum.each(@query_funcs, fn query_func ->
        func = """
        def caller(%{"sql" => sql}) do
          #{query_func}(Repo, sql, [])
        end
        """

        {_, ast} = Code.string_to_quoted(func)

        assert Query.parse_sql_def(ast, query_func, true) |> vuln?
      end)
    end

    test "do not affect qualified calls, which are matched either way" do
      Enum.each(@query_funcs, fn query_func ->
        func = """
        def caller(%{"sql" => sql}) do
          Repo.#{query_func}(sql)
        end
        """

        {_, ast} = Code.string_to_quoted(func)

        assert Query.parse_repo_query_def(ast, query_func) |> vuln?
        assert Query.parse_repo_query_def(ast, query_func, true) |> vuln?
      end)
    end
  end
end
