defmodule SobelowTest.DOS.ListToAtomTest do
  use ExUnit.Case
  import Sobelow, only: [vuln?: 1]
  alias Sobelow.DOS.ListToAtom

  test "Unsafe `List.to_atom`" do
    func = """
    def index(conn, %{"test" => test}) do
      render conn, List.to_atom(test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert ListToAtom.parse_def(ast) |> vuln?
  end

  test "Unsafe indirect `List.to_atom`" do
    func = """
    def index(conn, params) do
      render conn, List.to_atom(params["test"])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert ListToAtom.parse_def(ast) |> vuln?
  end

  test "Unsafe `:erlang.list_to_atom`" do
    func = """
    def index(conn, %{"test" => test}) do
      render conn, :erlang.list_to_atom(test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert ListToAtom.parse_def_erlang(ast) |> vuln?
  end

  test "Unsafe piped `:erlang.list_to_atom`" do
    func = """
    def index(conn, %{"test" => test}) do
      render conn, test |> :erlang.list_to_atom()
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert ListToAtom.parse_def_erlang(ast) |> vuln?
  end

  test "reports captured `:erlang.list_to_atom` by its capture argument" do
    func = """
    def index(conn, _params) do
      render conn, Enum.map([~c"index"], &:erlang.list_to_atom/1)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert {[{_, ["&1"]}], _, _} = ListToAtom.parse_def_erlang(ast)
  end

  test "Unsafe multi-stage piped `:erlang.list_to_atom`" do
    func = """
    def index(conn, %{"test" => test}) do
      render conn, test |> String.trim() |> :erlang.list_to_atom()
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert ListToAtom.parse_def_erlang(ast) |> vuln?
  end

  test "keeps Elixir and Erlang calls apart, each with its own line" do
    func = """
    def index(conn, %{"a" => a, "b" => b, "c" => c}) do
      x = :erlang.list_to_atom(a)
      y = List.to_atom(b)
      z = c |> :erlang.list_to_atom()
      render conn, [x, y, z]
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert [{3, [:b]}] = lines_and_vars(ListToAtom.parse_def(ast))
    assert [{2, [:a]}, {4, [:c]}] = lines_and_vars(ListToAtom.parse_def_erlang(ast))
  end

  test "safe `:erlang.list_to_atom`" do
    func = """
    def index(conn, params) do
      render conn, :erlang.list_to_atom("index")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute ListToAtom.parse_def_erlang(ast) |> vuln?
  end

  test "safe `String.to_atom`" do
    func = """
    def index(conn, params) do
      render conn, List.to_atom("index")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute ListToAtom.parse_def(ast) |> vuln?
  end

  defp lines_and_vars({vulns, _params, _meta}) do
    vulns
    |> Enum.map(fn {vuln, var} -> {Sobelow.Parse.get_fun_line(vuln), var} end)
    |> Enum.sort()
  end
end
