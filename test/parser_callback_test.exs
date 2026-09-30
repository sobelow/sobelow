defmodule Sobelow.ParserCallbackTest do
  use Sobelow.CoverageCase, async: false

  test "qualified traversal callbacks retain capture arity and reject other aliases" do
    ast = quoted("Enum.map(paths, &File.read/1)")

    for callback <- [:get_aliased_funs_of_type, :get_strict_aliased_funs_of_type] do
      {_, [sink]} =
        Macro.prewalk(ast, [], &apply(Parse, callback, [&1, &2, :read, [:File]]))

      assert Macro.to_string(sink) == "File.read(&1)"

      assert {_, []} =
               Macro.prewalk(ast, [], &apply(Parse, callback, [&1, &2, :read, [:Other]]))
    end
  end

  test "Erlang traversal and pipe helpers agree on the original sink" do
    ast = quoted("def unsafe(input), do: input |> :erlang.binary_to_atom(:utf8)")

    {_, [sink]} =
      Macro.prewalk(ast, [], &Parse.get_erlang_funs_of_type(&1, &2, :binary_to_atom, :erlang))

    assert Parse.get_erlang_aliased_funs_of_type(ast, :binary_to_atom, :erlang) == [sink]
    assert Parse.get_erlang_funs_from_pipe(ast, :binary_to_atom, :erlang) == [sink]
    assert Parse.get_piped_erlang_aliased_funs_of_type(sink, :binary_to_atom, :erlang) == [sink]
    assert Parse.get_piped_erlang_aliased_funs_of_type(sink, :binary_to_atom, :other) == []
  end

  test "qualified pipe matchers preserve legacy and resolved alias decisions" do
    legacy = quoted("Other.File.read(path)")
    assert Parse.get_piped_aliased_funs_of_type(legacy, :read, :File) == [legacy]
    assert Parse.get_piped_aliased_funs_of_type(legacy, :read, [:File]) == []

    renamed = quoted("FS.read(path)")

    Sobelow.Lexical.with_context(%{renamed => %{module: [:File]}}, fn ->
      assert Parse.get_piped_aliased_funs_of_type(renamed, :read, [:File]) == [renamed]
      assert Parse.get_piped_aliased_funs_of_type(renamed, :read, :File) == [renamed]
      assert Parse.get_piped_aliased_funs_of_type(renamed, :write, :File) == []
    end)
  end

  test "top-level traversal prunes nested calls while ordinary traversal retains them" do
    outer = quoted("read(read(path))")
    [inner] = elem(outer, 2)

    assert {_, [^inner, ^outer]} =
             Macro.prewalk(outer, [], &Parse.get_funs_of_type(&1, &2, :read))

    assert {[], [^outer]} =
             Macro.prewalk(outer, [], &Parse.get_top_level_funs_of_type(&1, &2, :read))

    assert Parse.get_piped_funs_of_type(outer, :read) == [outer]
    assert Parse.get_piped_funs_of_type(outer, :write) == []
  end

  test "pipe-value traversal consumes the matched pipe and retains the input variable" do
    ast = quoted("input |> File.read()")
    [_input, sink] = elem(ast, 2)
    assert {[], [[:input]]} = Macro.prewalk(ast, [], &Parse.get_pipe_val(&1, &2, sink))
  end

  test "template callbacks retain complete raw pipes and render assignments" do
    ast = quoted("value |> Phoenix.HTML.raw()")
    [_value, call] = elem(ast, 2)

    assert {^ast, %{ast: ^ast, raw: [^call, ^ast]}} =
             Macro.prewalk(ast, %{ast: ast, raw: []}, &Parse.get_meta_template_fun/2)

    render = quoted(~s|render(conn, :show, body: input, fixed: "literal")|)

    assert {^render, [body: input, fixed: "literal"]} =
             Macro.prewalk(render, [], &Parse.extract_render_opts/2)

    assert {:input, _, nil} = input
  end
end
