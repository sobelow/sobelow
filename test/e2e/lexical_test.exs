defmodule Sobelow.LexicalTest do
  use Sobelow.ScanCase, async: false

  test "renamed aliases detect qualified and imported SQL calls" do
    path =
      temp_fixture_file("basic", "lib/queries.ex", """
      defmodule Queries do
        alias Ecto.Adapters.SQL, as: DB
        import DB, only: [query: 3]
        def qualified(sql), do: DB.query(Repo, sql, [])
        def imported(sql), do: query(Repo, sql, [])
        def piped(sql), do: Repo |> query(sql, [])
      end
      """)

    results =
      scan("basic")
      |> findings_for("SQL.Query")
      |> Enum.filter(&String.ends_with?(&1["file"], path))

    assert Enum.map(results, & &1["line"]) == [4, 5, 6]
  end

  test "unrelated aliases, excluded arities and local imports stay in scope" do
    path =
      temp_fixture_file("basic", "lib/scoped_queries.ex", """
      defmodule ScopedQueries do
        alias Other.SQL
        import SQL
        def unrelated(sql), do: query(Repo, sql, [])
        def local(sql) do
          import Ecto.Adapters.SQL, only: [query: 3]
          query(Repo, sql, [])
        end
        def outside(sql), do: query(Repo, sql, [])
        def excluded(sql) do
          import Ecto.Adapters.SQL, except: [query: 3]
          query(Repo, sql, [])
        end
      end
      """)

    results =
      scan("basic")
      |> findings_for("SQL.Query")
      |> Enum.filter(&String.ends_with?(&1["file"], path))

    assert Enum.map(results, & &1["line"]) == [7]
  end

  test "aliases for standard library sinks retain the original finding AST" do
    path =
      temp_fixture_file("basic", "lib/commands.ex", """
      defmodule Commands do
        alias System, as: OS
        def run(cmd), do: OS.cmd(cmd, [])
      end
      """)

    assert [_] =
             scan("basic")
             |> findings_for("CI.System")
             |> Enum.filter(&String.ends_with?(&1["file"], path))
  end

  test "grouped aliases and nested modules inherit lexical declarations" do
    path =
      temp_fixture_file("basic", "lib/nested_queries.ex", """
      defmodule Parent do
        alias Ecto.Adapters.{SQL}
        import SQL, only: [query: 3, query!: 3]
        import SQL, except: [query!: 3]
        defmodule Child do
          def read(sql), do: SQL.query(Repo, sql, [])
          def imported(sql), do: query(Repo, sql, [])
          def excluded(sql), do: query!(Repo, sql, [])
        end
      end
      """)

    results =
      scan("basic")
      |> findings_for("SQL.Query")
      |> Enum.filter(&String.ends_with?(&1["file"], path))

    assert Enum.map(results, & &1["line"]) == [6, 7]
  end

  test "aliases for response connections are used by content type analysis" do
    path =
      temp_fixture_file("basic", "lib/aliased_response.ex", """
      defmodule Response do
        alias Plug.Conn, as: PC
        def json(conn, input), do: conn |> PC.put_resp_content_type("application/json") |> PC.send_resp(200, input)
        def html(conn, input), do: conn |> PC.put_resp_content_type("text/html") |> PC.send_resp(200, input)
      end
      """)

    results =
      scan("basic")
      |> findings_for("XSS.SendResp")
      |> Enum.filter(&String.ends_with?(&1["file"], path))

    assert Enum.map(results, & &1["line"]) == [4]
  end

  test "unresolved import selectors remain low confidence without crashing" do
    path =
      temp_fixture_file("basic", "lib/dynamic_import.ex", """
      defmodule DynamicImport do
        use BasicWeb, :controller
        import Ecto.Adapters.SQL, only: @queries
        def read(sql), do: query(Repo, sql, [])
      end
      """)

    results =
      scan("basic")
      |> findings_for("SQL.Query")
      |> Enum.filter(&String.ends_with?(&1["file"], path))

    assert [%{"confidence" => "low"}] = results
  end

  test "nonliteral directives do not abort an otherwise scannable source" do
    temp_fixture_file("basic", "lib/nonliteral_directives.ex", """
    defmodule Directives do
      alias variable.{SQL}
      import Ecto.Adapters.SQL, options()
      def read(path), do: File.read(path)
    end
    """)

    assert scan("basic")["total_findings"] > 10
  end
end
