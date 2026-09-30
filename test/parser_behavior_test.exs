defmodule Sobelow.ParserBehaviorTest do
  use Sobelow.CoverageCase, async: false

  @tag :tmp_dir
  test "legacy metadata entry point supports private definitions and unreadable templates", %{
    tmp_dir: dir
  } do
    path = Path.join(dir, "module.ex")
    File.write!(path, "defmodule Example do\n defp private(value), do: File.read(value)\nend")
    assert [definition] = Parse.get_meta_funs(path).def_funs
    assert elem(definition, 0) == :defp
    missing = Path.join(dir, "missing.html.eex")

    output =
      capture_io(:stderr, fn ->
        assert Parse.get_meta_template_funs(missing) == %{raw: [], ast: {}}
      end)

    assert output =~ "Could not read"
    template = Path.join(dir, "page.html")
    File.write!(template, "<%= @body |> raw() %>")
    assert Parse.get_meta_template_funs(template).raw |> Parse.get_template_vars() == ["@body"]
  end

  test "guarded function declarations preserve parameter names and locations" do
    assert Parse.get_fun_declaration(
             quoted("def read(path) when is_binary(path), do: File.read(path)")
           ) == {[:path], {:read, 1}}

    ast = {:def, [], nil}
    meta = Parse.get_meta_funs(quoted("def public(), do: :ok"))
    assert Parse.get_meta_funs(ast, meta) == {ast, meta}
    assert Parse.get_meta_funs({:defp, [], nil}, meta) == {{:defp, [], nil}, meta}
  end

  test "module call and assignment helpers preserve full AST and ignore other modules" do
    ast =
      quoted(
        "conn = Plug.Conn.put_resp_header(conn, \"header\", value)\nother = Other.Conn.call(conn)"
      )

    assert [sink] = Parse.get_funs_by_module(ast, [:Plug, :Conn])
    assert Macro.to_string(sink) =~ "Plug.Conn.put_resp_header"
    assert Parse.get_assigns_from(ast, [:Plug, :Conn]) == [:conn]
    assert Parse.get_assigns_from(ast, [:Missing]) == []
  end

  test "option extraction supports interpolation, assigns, accessors and connection params" do
    assert Parse.extract_opts(quoted("send_resp")) == []
    assert Parse.extract_opts(quoted("send_resp(conn, 200, value)")) == :value
    assert Parse.extract_opts({:call, [], []}) == [:call]
    assert Parse.extract_opts([quoted("value"), quoted("@attribute")]) == [:value, []]
    assert Parse.extract_opts(quoted("call(value, @attribute)")) == [:value, []]
    assert Parse.extract_opts({:call, [], nil}, 0) == []
    assert Parse.extract_opts(quoted("call(conn.params[\"key\"])"), 0) == "conn.params"
    assert Parse.extract_opts(quoted("call(conn.params)"), 0) == :conn
    assert Parse.extract_opts({:call, [], [{:., [], [{:conn, [], nil}, :params]}]}, 0) == :conn

    assert Parse.extract_opts(quoted("call(:erlang.apply(module, function, args))"), 0) == [
             [],
             []
           ]

    assert Parse.extract_opts(quoted("call(~s(literal))"), 0) == []
    assert Parse.extract_opts(quoted("call(~e(literal))"), 0) == []

    interpolation =
      {:<<>>, [], [{:value, [], nil}, {{:., [], [Kernel, :to_string]}, [], [{:other, [], nil}]}]}

    assert Parse.extract_opts(interpolation) == [:value, [:other]]
    assert Parse.extract_opts({:call, [], [interpolation]}, 0) == [:value, :other]
    assert Parse.extract_opts({:<<>>, [], [{:<<>>, [], [{:value, [], nil}]}]}) == [[:value]]
  end

  test "captures, missing bodies and do-block pipes preserve historical call selection" do
    [capture] = Parse.get_top_level_funs_of_type(quoted("&read/1"), :read)
    assert Macro.to_string(capture) == "read(&1)"
    assert Parse.get_funs_of_type({:def, [], [{:read, [], []}]}, :read) == []

    assert Sobelow.FunctionAnalysis.with_fun({:def, [], [{:read, [], []}]}, fn ->
             Parse.get_funs_of_type({:def, [], [{:read, [], []}]}, :read)
           end) == []

    pipe = quoted("value |> block(do: read(path))")
    assert Parse.get_pipe_funs(pipe) == []
    assert Parse.get_pipe_val(quoted("other |> unrelated()"), quoted("absent()")) == []
    ast = quoted("wrap(value |> read()) |> other()")
    [sink] = Parse.get_funs_of_type(ast, :read)
    assert Parse.get_pipe_val(ast, sink) != []

    Sobelow.Lexical.with_context(%{}, fn ->
      assert [_] = Parse.get_aliased_funs_of_type(quoted("File.read(path)"), :read, [:File])
    end)
  end

  test "render options separate parameter, connection and local assignments" do
    render =
      quoted(
        ~s|render(conn, "page.html", message: input, local: load(), literal: "safe", reflected: conn.params["body"])|
      )

    assert Parse.parse_render_opts(render, [:input], 1) ==
             {"page.html", [:message, :reflected], [:local, nil]}

    assert Parse.conn_params?({:body, quoted(~s(conn.params["body"]))})
    refute Parse.conn_params?({:body, quoted("other.body")})
  end

  test "formatting unusual error terms retains location and token text" do
    assert Parse.format_error(:unexpected, "token") == ":unexpectedtoken"
    assert Parse.format_location(line: 3) == "3:"
  end
end
