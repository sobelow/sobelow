defmodule Sobelow.LexicalKeysTest do
  use ExUnit.Case, async: true
  alias Sobelow.Lexical

  test "equal map arguments resolve equally even when constructed in different orders" do
    meta = [line: 1, column: 1]
    arguments = for key <- 1..40, do: {key, key}
    call = {{:., meta, [{:__aliases__, meta, [:FS]}, :read]}, meta, [Map.new(arguments)]}

    equivalent =
      {{:., meta, [{:__aliases__, meta, [:FS]}, :read]}, meta, [Map.new(Enum.reverse(arguments))]}

    fun = {:def, [], [{:read, [], []}, [do: call]]}

    ast =
      {:__block__, [],
       [{:alias, [], [{:__aliases__, [], [:File]}, [as: {:__aliases__, [], [:FS]}]]}, fun]}

    context = Map.fetch!(Lexical.functions(ast), fun)
    Lexical.with_context(context, fn -> assert Lexical.matches?(equivalent, [:File]) end)
  end

  test "legacy contexts keyed by AST retain their meaning" do
    call = Code.string_to_quoted!("FS.read(path)", columns: true)

    Lexical.with_context(%{call => %{module: [:File]}}, fn ->
      assert Lexical.matches?(call, [:File])
    end)
  end

  test "AST keys remain available when deterministic encoding is unavailable" do
    Process.put({Lexical, :binary_keys}, false)

    ast =
      Code.string_to_quoted!(
        """
        alias File, as: FS
        def read(path), do: FS.read(path)
        """,
        columns: true
      )

    [{fun, context}] = Map.to_list(Lexical.functions(ast))

    {_, calls} =
      Macro.prewalk(fun, [], fn
        {{:., _, _}, _, _} = node, calls -> {node, [node | calls]}
        node, calls -> {node, calls}
      end)

    assert Map.has_key?(context, hd(calls))
    Lexical.with_context(context, fn -> assert Lexical.matches?(hd(calls), [:File]) end)
  end
end
