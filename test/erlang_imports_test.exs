defmodule Sobelow.ErlangImportsTest do
  use ExUnit.Case, async: true
  alias Sobelow.Lexical
  alias Sobelow.Parse

  # Returns the reported sink lines per function name, in source order.
  defp sinks(source, type \\ :cmd, module \\ :os) do
    ast = Code.string_to_quoted!(source, columns: true)

    ast
    |> Lexical.functions()
    |> Enum.map(fn {{_, _, [head | _]} = fun, context} ->
      {vars, _params, _meta} =
        Lexical.with_context(context, fn ->
          Parse.get_erlang_fun_vars_and_meta(fun, 0, type, module)
        end)

      lines = vars |> Enum.map(fn {node, _vars} -> Keyword.get(elem(node, 1), :line) end)
      {fun_name(head), Enum.sort(lines)}
    end)
    |> Map.new()
  end

  defp fun_name({:when, _, [head | _]}), do: fun_name(head)
  defp fun_name({name, _, _}), do: name

  test "imported calls, pipes and captures are detected with their effective arities" do
    assert sinks("""
           defmodule M do
             import :os, only: [cmd: 1]
             def direct(x), do: cmd(x)
             def piped(x), do: x |> cmd()
             def named(xs), do: Enum.map(xs, &cmd/1)
             def anonymous(xs), do: Enum.map(xs, &cmd(&1))
             def qualified(x), do: :os.cmd(x)
           end
           """) == %{direct: [3], piped: [4], named: [5], anonymous: [6], qualified: [7]}
  end

  test "an import without options imports every function" do
    assert sinks("""
           defmodule M do
             import :os
             def run(x), do: cmd(x)
           end
           """) == %{run: [3]}
  end

  test "only and except selections respect names and arities" do
    assert sinks("""
           defmodule M do
             def other_arity(x) do
               import :os, only: [cmd: 2]
               cmd(x)
             end

             def other_arity_piped(x) do
               import :os, only: [cmd: 2]
               x |> cmd(:opts)
             end

             def excluded(x) do
               import :os, except: [cmd: 1]
               cmd(x)
             end

             def macros_only(x) do
               import :os, only: :macros
               cmd(x)
             end

             def functions_only(x) do
               import :os, only: :functions
               cmd(x)
             end
           end
           """) == %{
             other_arity: [],
             other_arity_piped: [9],
             excluded: [],
             macros_only: [],
             functions_only: [24]
           }
  end

  test "repeated imports replace or narrow the previous selection" do
    assert sinks("""
           defmodule M do
             def replaced(x) do
               import :os, only: [cmd: 1]
               import :os, only: [getenv: 1]
               cmd(x)
             end

             def narrowed(x) do
               import :os, only: [cmd: 1, getenv: 1]
               import :os, except: [cmd: 1]
               cmd(x)
             end

             def reimported(x) do
               import :os, except: [cmd: 1]
               import :os, only: [cmd: 1]
               cmd(x)
             end
           end
           """) == %{replaced: [], narrowed: [], reimported: [17]}
  end

  test "imports from different Erlang modules are tracked independently" do
    source = """
    defmodule M do
      import :os, only: [cmd: 1]
      import :erlang, only: [binary_to_term: 1]
      def run(x), do: cmd(x)
      def decode(x), do: binary_to_term(x)
    end
    """

    assert sinks(source) == %{run: [4], decode: []}
    assert sinks(source, :binary_to_term, :erlang) == %{run: [], decode: [5]}
  end

  test "imports apply only within their function and module scopes" do
    assert sinks("""
           defmodule Outer do
             def before(x), do: cmd(x)
             import :os, only: [cmd: 1]
             def after_import(x), do: cmd(x)

             defmodule Inner do
               def inherited(x), do: cmd(x)
             end
           end

           defmodule Sibling do
             def late(x) do
               cmd(x)
               import :os
             end

             def local(x) do
               import :os
               cmd(x)
             end

             def outside(x), do: cmd(x)
           end
           """) == %{
             before: [],
             after_import: [4],
             inherited: [7],
             late: [],
             local: [19],
             outside: []
           }
  end

  test "unrelated imports and local functions with the same name are not sinks" do
    assert sinks("""
           defmodule M do
             import Shell, only: [cmd: 1]
             import :shell
             def unrelated(x), do: cmd(x)
             def piped(x), do: x |> cmd()
             def captured(xs), do: Enum.map(xs, &cmd/1)
           end

           defmodule Local do
             def run(x), do: cmd(x)
             defp cmd(x), do: x
           end
           """) == %{unrelated: [], piped: [], captured: [], run: [], cmd: []}
  end

  test "bare calls are not matched without lexical context" do
    {:ok, fun} = Code.string_to_quoted("def run(x), do: cmd(x)")
    assert {[], _params, _meta} = Parse.get_erlang_fun_vars_and_meta(fun, 0, :cmd, :os)
  end
end
