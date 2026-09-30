defmodule SobelowTest.XSS.RawTemplateTest do
  use ExUnit.Case
  import Sobelow, only: [vuln?: 1]
  alias Sobelow.XSS.Raw

  test "vulnerable raw in template" do
    temp = """
    <%= raw(@user_input) %>
    """

    ast = EEx.compile_string(temp)

    assert Raw.parse_raw_def(ast) |> vuln?
  end

  test "vulnerable piped raw in template" do
    temp = """
    <%= @user_input |> raw() %>
    """

    ast = EEx.compile_string(temp)

    assert Raw.parse_raw_def(ast) |> vuln?
  end

  test "safe raw in template" do
    temp = """
    <%= raw("<h1>Test</h1>") %>
    """

    ast = EEx.compile_string(temp)

    refute Raw.parse_raw_def(ast) |> vuln?
  end

  @tag :tmp_dir
  test "a closing brace inside an HEEx string does not hide raw", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "index.html.heex")
    File.write!(path, "<span>{raw(@name <> \"}\")}</span>")

    meta = Sobelow.Parse.get_meta_template_funs(path)

    assert Enum.any?(meta.raw, fn ast ->
             {vars, _, _} = Raw.parse_raw_def([ast])
             vars != []
           end)
  end

  test "inline sigils detect legacy EEx expressions and retain source lines" do
    ast = Code.string_to_quoted!(~s|def render(assigns), do: ~H"<%= raw(@name) %>"|)
    assert [raw] = Sobelow.Parse.get_heex_raw_funs(ast)
    assert Sobelow.Parse.get_fun_line(raw) == 1
  end

  @tag :tmp_dir
  test "HEEx comments and disabled interpolation do not produce raw findings", %{tmp_dir: dir} do
    path = Path.join(dir, "disabled.html.heex")

    File.write!(path, """
    <%!-- {raw(@comment)} --%>
    <script>{raw(@script)}</script>
    <style>{raw(@style)}</style>
    <section phx-no-curly-interpolation><div>{raw(@disabled)}</div></section>
    <div>{raw(@enabled)}</div>
    """)

    assert [raw] = Sobelow.Parse.get_meta_template_funs(path).raw
    assert Sobelow.Parse.get_fun_line(raw) == 5
  end

  @tag :tmp_dir
  test "nested sigils and Elixir comments do not terminate an expression", %{tmp_dir: dir} do
    path = Path.join(dir, "nested.html.heex")
    File.write!(path, ~S|{raw(@name <> ~s"}") # a closing brace }
    }|)
    assert [_] = Sobelow.Parse.get_meta_template_funs(path).raw
  end

  @tag :tmp_dir
  test "attribute comparisons and quoted comment markers preserve raw locations", %{tmp_dir: dir} do
    path = Path.join(dir, "attributes.html.heex")
    File.write!(path, ~S|<div title={raw(if @count > 0, do: @name, else: " # }")}></div>|)
    assert [raw] = Sobelow.Parse.get_meta_template_funs(path).raw
    assert Sobelow.Parse.get_fun_column(raw) == 13
  end

  test "inline sigils recognize qualified EEx raw and skip malformed EEx" do
    ast = Code.string_to_quoted!(~s|def render(assigns), do: ~H"<%= Phoenix.HTML.raw(@name) %>"|)
    assert [_] = Sobelow.Parse.get_heex_raw_funs(ast)
    ast = Code.string_to_quoted!(~s|def render(assigns), do: ~H"<%= if true do %>"|)
    assert [] = Sobelow.Parse.get_heex_raw_funs(ast)
  end

  test "inline brace columns include sigil prefixes and heredoc indentation" do
    ast = Code.string_to_quoted!(~s|def render(assigns), do: ~H"{raw(@name)}"|, columns: true)
    assert [raw] = Sobelow.Parse.get_heex_raw_funs(ast)
    assert Sobelow.Parse.get_fun_column(raw) == 30

    ast =
      Code.string_to_quoted!(
        "def render(assigns) do\n    ~H\"\"\"\n    <div>{raw(@name)}</div>\n    \"\"\"\nend",
        columns: true
      )

    assert [raw] = Sobelow.Parse.get_heex_raw_funs(ast)
    assert Sobelow.Parse.get_fun_column(raw) == 11
  end
end
