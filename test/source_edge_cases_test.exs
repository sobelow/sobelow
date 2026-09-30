defmodule Sobelow.SourceEdgeCasesTest do
  use Sobelow.CoverageCase, async: false
  alias Sobelow.{HEEx, Utils}
  alias Sobelow.XSS.SendResp

  test "HTML text, unmatched closing tags and incomplete tags retain earlier interpolations" do
    ast = HEEx.ast("</unknown><input/><span>{raw(@value)}</span>1 < 2 <unfinished", "page.heex")
    assert [raw] = Parse.get_funs_of_type(ast, :raw)
    assert Parse.get_fun_line(raw) == 1
    assert Parse.get_fun_column(raw) == 26
  end

  test "malformed HEEx attributes and invalid UTF8 raise actionable syntax errors" do
    assert_raise EEx.SyntaxError, ~r/column/, fn ->
      HEEx.ast("<span title={broken(}", "broken.heex")
    end

    assert_raise EEx.SyntaxError, ~r/column 1/, fn -> HEEx.ast(<<255>>, "broken.heex") end
  end

  test "escaped EEx markers can end in literal text without a closing delimiter" do
    ast = HEEx.ast("<%% literal EEx marker", "page.heex")
    assert Parse.get_funs_of_type(ast, :raw) == []
    assert Macro.to_string(ast) =~ "literal EEx marker"
  end

  test "piped binary downloads remain excluded from directory traversal findings" do
    fun = quoted("def download(conn, bytes), do: conn |> send_download({:binary, bytes})")
    assert {[], [:conn, :bytes], {:download, 1}} = Sobelow.Traversal.SendDownload.parse_def(fun)
  end

  test "content-type extraction accepts piped argument shapes and absent arguments" do
    assert SendResp.get_content_type(
             quoted(~s|put_resp_content_type("text/html", charset: "utf8")|)
           ) == "text/html"

    assert SendResp.get_content_type(quoted(~s|put_resp_content_type("text/html")|)) ==
             "text/html"

    assert SendResp.get_content_type(quoted("put_resp_content_type()")) == nil
  end

  test "unknown function shapes and absent sinks retain response confidence" do
    finding = Finding.init("XSS.SendResp: XSS", "page.ex", :high)
    assert SendResp.set_confidence(finding).confidence == :high

    assert SendResp.set_confidence(%{
             finding
             | fun_source: quoted("def show(conn), do: other(conn)"),
               vuln_source: quoted("send_resp(conn, 200, value)")
           }).confidence == :high

    fun =
      quoted("def show(conn), do: send_resp(put_resp_content_type(conn, dynamic()), 200, value)")

    [sink] = Parse.get_funs_of_type(fun, :send_resp)

    assert SendResp.set_confidence(%{finding | fun_source: fun, vuln_source: sink}).confidence ==
             :low

    fun = quoted("def show(conn), do: send_resp(build_conn(), 200, value)")
    [sink] = Parse.get_funs_of_type(fun, :send_resp)

    assert SendResp.set_confidence(%{finding | fun_source: fun, vuln_source: sink}).confidence ==
             :high
  end

  @tag :tmp_dir
  test "project names support binaries and unresolved values without evaluation", %{tmp_dir: dir} do
    path = Path.join(dir, "mix.exs")
    File.write!(path, ~s|def project, do: [app: "literal"]|)
    assert Utils.get_app_name(path) == "literal"
    File.write!(path, "def project, do: [app: dynamic()]")
    assert Utils.get_app_name(path) == {:dynamic, [line: 1, column: 24], []}
    refute Utils.imports?([quoted("not_an_import()")], [:Ecto, :Repo])
    refute Utils.imports?([{:import, [], [{:__aliases__, [], []}]}], [:Ecto, :Repo])
    assert Sobelow.Config.Secrets.env_var?("${SECRET}")
    refute Sobelow.Config.Secrets.env_var?("${unfinished")
  end

  test "finding macros retain generated IDs, help text and category registration" do
    module = Module.concat(Sobelow, "CoverageExample")

    on_exit(fn ->
      :code.purge(module)
      :code.delete(module)
    end)

    Code.compile_string("""
    defmodule #{inspect(module)} do
      @moduledoc "First paragraph.\n\nSecond paragraph."
      @uid 999
      @finding_type "Example.Check: Example"
      use Sobelow.Finding
    end
    """)

    assert module.id() == "SBLW999"
    assert module.rule().name == "Example.Check"
    assert module.rule().help.text =~ "Second paragraph."
    category = Module.concat(Sobelow, "CoverageCategory")

    on_exit(fn ->
      :code.purge(category)
      :code.delete(category)
    end)

    Code.compile_string("""
    defmodule #{inspect(category)} do
      @submodules [#{inspect(module)}]
      use Sobelow.FindingType
    end
    """)

    assert category.finding_modules() == [module]
    assert category.details() == [module.details()]
    assert category.rules() == [module.rule()]
  end
end
