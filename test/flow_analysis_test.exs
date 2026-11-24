defmodule Sobelow.FlowAnalysisTest do
  use ExUnit.Case, async: true

  alias Sobelow.Lexical
  alias Sobelow.Parse.Flow.{Eval, LiveView, Pattern, Value}
  alias Sobelow.Parse.Flow

  defp ast(source), do: Code.string_to_quoted!(source, columns: true)

  defp evaluate(source) do
    state = %{flows: %{}, fuel: 256}
    fun = %{file: "flow.ex", module: [:Example], name: :show, arity: 2}
    ctx = %{fun: fun, functions: %{}, stack: [], source: Eval.site(fun, ast("input"), "request")}
    env = %{input: {[], Value.input()}}

    {result, _, state} = Eval.eval(ast(source), env, ctx, state)
    {result, state.flows}
  end

  defp result(source), do: elem(evaluate(source), 0)

  test "unknown fields preserve explicit overwrites and literal Map.get defaults" do
    key = Value.literal(:name)
    unknown_map = Value.input()
    default = Value.literal("fixed")

    assert Value.map_call(:get, [unknown_map, key, default]) ==
             Value.union([unknown_map, default])

    updated = Value.map_call(:put, [unknown_map, key, Value.unknown()])
    assert Value.map_call(:get, [updated, key]) == Value.unknown()
    assert Value.field(updated, :other) == unknown_map
    assert Value.map_call(:get, [Value.tag(:map), key, default]) == default
    assert Value.map_call(:get, [unknown_map, Value.unknown()]) == Value.unknown()

    assert [ok, error] = Value.map_call(:fetch, [unknown_map, key])
    assert Value.field([ok], 1) == unknown_map
    assert [error] == Value.literal(:error)
    assert Value.map_call(:fetch, [Value.tag(:map), key]) == [error]

    for {op, args} <- [get: [key, unknown_map], put: [key, unknown_map], fetch: [key]] do
      assert Value.map_call(op, [Value.literal(nil) | args]) == []
    end
  end

  test "matching known shapes distinguishes incompatible tags, absent keys and unknown fields" do
    [tuple] = Value.aggregate({:tuple, 2}, [{0, Value.literal(:ok)}, {1, Value.unknown()}])
    [map] = Value.aggregate(:map, name: Value.input())
    [literal] = Value.literal(false)
    assert Value.known?(tuple, ast("{:ok, 1}")) == :maybe
    assert Value.known?(tuple, ast("{:ok, x}")) == :yes
    assert Value.known?(tuple, ast("%{}")) == :no
    assert Value.known?(map, ast("{:ok, x}")) == :no
    assert Value.known?(map, false) == :no
    assert Value.known?(map, ast("%{missing: x}")) == :no
    assert Value.known?(map, ast("%{^key => x}")) == :maybe
    assert Value.known?(literal, ast("%{name: name}")) == :no
    assert Value.known?(literal, ast("^pinned")) == :maybe
    refute Value.literal_entry?(ast("unquote_splicing(fields)"))
    assert Pattern.supported?(ast("whole = {:ok, :tag, %{name: name}}"))
    refute Pattern.supported?(ast("[item]"))
    assert Value.known?(tuple, ast("whole = {:ok, value}")) == :yes
    assert Value.known?(tuple, ast("whole = {:error, value}")) == :no
    assert Value.known?(tuple, ast("{:error, value} = whole")) == :no
    assert Value.known?(tuple, ast("{:ok, false} = whole")) == :maybe
  end

  test "bounded shapes and evidence stop carrying paths after the analysis limits" do
    large = Enum.reduce(1..128, Value.tag(:map), &Value.put(&2, &1, Value.input()))
    assert large == Value.unknown()
    deep = Enum.reduce(1..15, Value.input(), fn _, v -> Value.aggregate(:map, key: v) end)
    assert Enum.reduce(1..15, deep, fn _, v -> Value.field(v, :key) end) == Value.unknown()
    assert Enum.reduce(1..49, Value.input(), &Value.step(&2, &1)) == Value.unknown()
    choices = Value.union(for v <- 1..20, do: Value.literal(v))
    assert length(choices) == 8
  end

  test "pinned and sibling patterns preserve outer bindings across reassignments" do
    env = %{old: {[], Value.input()}, other: {[], Value.literal(1)}}
    pair = Value.aggregate({:tuple, 2}, [{0, Value.input()}, {1, Value.literal(0)}])
    matched = Pattern.bind(ast("whole = {name, ^other}"), pair, env)
    assert Pattern.read(matched, :whole) == pair
    assert Pattern.read(matched, :name) == Value.input()
    assert Pattern.read(matched, :other) == Value.literal(1)
    cleared = Pattern.bind(ast("[old, ^other]"), Value.unknown(), matched)
    assert Pattern.read(cleared, :old) == Value.unknown()
    assert Pattern.read(cleared, :other) == Value.literal(1)
    assert Pattern.merge_writes(matched, cleared, matched) == cleared
    assert Pattern.merge_writes(env, matched, env) == matched
    assert Pattern.bind(ast("%{unquote_splicing(fields)}"), Value.input(), env) == env
  end

  test "only reachable boolean arms and valid strict operands can contribute evidence" do
    for source <- [
          "if %{}, do: input, else: nil",
          "unless false, do: input",
          "unless {:ok, 0}, do: nil, else: input",
          "if input, do: input",
          "true and input",
          "false or input",
          "input || false",
          "input && input"
        ] do
      assert Value.trails(result(source)) != [], source
    end

    for source <- [
          "false && input",
          "true || input",
          "unless true, do: input",
          "input and nil",
          "input or nil",
          "input && false"
        ] do
      assert Value.trails(result(source)) == [], source
    end

    assert result("1 and input") == []
    assert result("%{} or input") == []
    assert elem(evaluate("false && File.read(input)"), 1) == %{}
  end

  test "with and case isolate bindings and stop evaluating an impossible match" do
    assert result("with {:ok, x} <- :error, do: x") == Value.literal(:error)
    assert result("with x = 1, {:ok, _} = :error, do: x") == []
    assert result("with x = 1, do: x") == Value.literal(1)
    assert result("case 1 do x when false -> input; _ -> nil end") == Value.literal(nil)
    assert result("case 1 do x when true -> x; _ -> input end") == Value.literal(1)
    assert result("case 1 do :error when flag -> input; _ -> 0 end") == Value.literal(0)
    maybe = result("case 1 do x when flag -> x; _ -> 0 end")
    assert maybe == Value.union([Value.literal(1), Value.literal(0)])
    assert result("with([:unsupported])") == Value.unknown()
    assert result("with(x)") == Value.unknown()
    assert result("case 1 do :unsupported end") == Value.unknown()
    assert evaluate("a = input\n{:ok, _} = :error\nFile.read(a)") == {[], %{}}
    assert evaluate("File.read({:ok, _} = :error)") == {[], %{}}
  end

  test "sibling arguments read their original bindings and export their writes" do
    assert result("x = input\n{(x = 1), x}") |> Value.field(1) |> Value.trails() != []
    assert result("x = input\nopaque(x = 1, x)\nx") == Value.literal(1)
    assert result("x = input\n%{(x = 1) => x}\nx") == Value.literal(1)
    assert result("%{unquote_splicing(fields)}") == Value.unknown()
    assert result("handler.(input)") == Value.unknown()
    assert result("Unknown.read()") == Value.unknown()
    assert result("receive do x -> input end") == Value.unknown()
  end

  test "helper registry includes opaque heads and skips dynamically generated names" do
    source = """
    defmodule Elixir.Example do
      defdelegate get(value), to: Elsewhere
      def unquote(name)(x), do: x
      def guarded(x) when is_binary(x), do: x
      def nested(x), do: x.body["value"]
      def remote, do: Other.value()
    end
    """

    defs = Flow.definitions(ast(source), "example.ex", %{})
    assert Enum.map(defs, & &1.name) == [:get, :guarded, :nested, :remote]
    assert hd(defs).body == :opaque
    assert Enum.at(defs, 1).guarded?
    assert Enum.at(defs, 2).return == {:param, :x, [:body, "value"]}
    assert Enum.at(defs, 3).return == :interpret
  end

  test "LiveView ownership requires a known unshadowed assign and a supported return" do
    call = ast("assign(s, :key, v)")

    for {imports, allowed} <- [
          {%{[:Other] => {:only, [assign: 3]}}, false},
          {%{[:Phoenix, :Component] => {:except, [assign: 3]}}, false},
          {%{[:Phoenix, :Component] => {:only, [assign: 3]}}, true},
          {%{[:Other] => {:only, [assign: 2]}}, true}
        ] do
      Lexical.with_context(%{call => %{imports: imports}}, fn ->
        assert Lexical.live_assign?(call) == allowed
      end)
    end

    refute Lexical.live_assign?(call)
    assert Lexical.resolved_module(call) == nil
    assert LiveView.assign([Value.unknown()], call, %{file: "sample.ex"}) == Value.unknown()
    assert LiveView.raw_flows([:unsupported], Value.tag(:map), "sample.ex") == %{}
  end
end
