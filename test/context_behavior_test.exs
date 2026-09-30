defmodule Sobelow.ContextBehaviorTest do
  use Sobelow.CoverageCase, async: false
  alias Sobelow.{Lexical, Scan}

  test "scan helpers fall back outside a scan and detach restores the active snapshot" do
    assert Scan.stats() == %{}
    Sobelow.Fingerprint.put_ignore("ignored")
    assert Scan.ignored_fingerprint?("ignored")
    assert Scan.allowed_checks(:unknown, fn -> [:fallback] end) == [:fallback]
    assert Scan.map([], fn _ -> flunk("unexpected call") end) == []
    assert Scan.map([1], &(&1 + 1)) == [2]
    assert Scan.map([1, 2], &(&1 + 1)) == [2, 3]

    Scan.with_scan(fn ->
      Scan.configure([Sobelow.XSS])
      assert Scan.ignored(fn -> flunk("snapshot was not used") end) == []
      table = Scan.current()
      Scan.attach(nil, fn -> refute Scan.active?() end)
      assert Scan.current() == table
      assert Scan.allowed_checks(:unknown, fn -> [:fallback] end) == [:fallback]
    end)
  end

  test "a failed preparation worker propagates its exit and releases the scan table" do
    previous = Process.flag(:trap_exit, true)

    try do
      ExUnit.CaptureLog.capture_log(fn ->
        assert catch_exit(
                 Scan.with_scan(fn -> Scan.map([1, 2], fn _ -> exit(:worker_failed) end) end)
               ) == :worker_failed
      end)

      refute Scan.active?()
    after
      Process.flag(:trap_exit, previous)
    end
  end

  test "nested lexical contexts are restored after exceptions" do
    call = quoted("FS.read(path)")

    Lexical.with_context(%{call => %{module: [:File]}}, fn ->
      assert Lexical.matches?(call, :File)
      assert_raise RuntimeError, fn -> Lexical.with_context(%{}, fn -> raise "stop" end) end
      assert Lexical.matches?(call, :File)
    end)

    refute Lexical.active?()
    query = quoted("query(repo, value, [])")
    Lexical.with_context(%{query => %{imports: %{}}}, fn -> refute Lexical.uncertain?(query) end)
    Lexical.with_context(%{}, fn -> refute Lexical.uncertain?(query) end)
  end

  test "fully qualified aliases and functions-only imports resolve without uncertainty" do
    ast =
      quoted("""
      alias Elixir.File, as: FS
      import Ecto.Adapters.SQL, only: :functions
      def read(repo, value) do
        FS.read(value)
        query(repo, value, [])
      end
      """)

    [{fun, context}] = Map.to_list(Lexical.functions(ast))

    Lexical.with_context(context, fn ->
      assert [_] = Parse.get_aliased_funs_of_type(fun, :read, :File)
      [query] = Parse.get_funs_of_type(fun, :query)
      assert Lexical.unqualified?(query, :SQL)
      refute Lexical.uncertain?(query)
    end)
  end

  test "invalid import selectors and later exclusions remain conservative" do
    ast =
      quoted("""
      import Ecto.Adapters.SQL, only: ["invalid"]
      import Ecto.Adapters.SQL, except: [query: 3]
      alias unknown()
      alias unknown().{File}
      alias Foo.{File, :dynamic}
      def query_values(repo, value) do
        query(repo, value, [])
        query!(repo, value, [])
      end
      """)

    [{fun, context}] = Map.to_list(Lexical.functions(ast))

    Lexical.with_context(context, fn ->
      [query] = Parse.get_funs_of_type(fun, :query)
      [bang] = Parse.get_funs_of_type(fun, :query!)
      refute Lexical.unqualified?(query, :SQL)
      assert Lexical.unqualified?(bang, :SQL)
      assert Lexical.uncertain?(bang)
      refute Lexical.uncertain?(quoted("other()"))
    end)
  end

  test "invalid exclusions do not hide imported sinks" do
    ast =
      quoted(
        "import Ecto.Adapters.SQL, except: dynamic()\ndef run(repo, value), do: query(repo, value, [])"
      )

    [{fun, context}] = Map.to_list(Lexical.functions(ast))

    Lexical.with_context(context, fn ->
      [query] = Parse.get_funs_of_type(fun, :query)
      assert Lexical.unqualified?(query, :SQL)
      assert Lexical.uncertain?(query)
    end)
  end
end
