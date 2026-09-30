defmodule SobelowTest.XSS.RawTest do
  use ExUnit.Case, async: true
  alias Sobelow.{Finding, FunctionAnalysis, Lexical}
  alias Sobelow.XSS.Raw

  test "a local raw helper is not Phoenix.HTML.raw (issue 44)" do
    assert [] ==
             findings("""
             defmodule SobelowTest do
               def sobelow_test(arg), do: raw(arg)
               def raw(arg), do: 42
             end
             """)
  end

  test "local private helpers with defaults and guards cover pipes and named captures" do
    assert [] ==
             findings(~S"""
             defmodule Helpers do
               def direct(input), do: raw(input)
               def piped(input), do: input |> raw()
               def captured(inputs), do: Enum.map(inputs, &raw/1)
               defp raw(input, options \\ []) when is_binary(input), do: byte_size(input)
             end
             """)
  end

  test "a default declaration without a body still defines the local arities" do
    assert [] ==
             findings(~S"""
             defmodule Helpers do
               def direct(input), do: raw(input)
               def raw(input, options \\ [])
               def raw(input, _options), do: byte_size(input)
             end
             """)
  end

  test "a local helper does not hide qualified or aliased Phoenix calls" do
    results =
      findings("""
      defmodule Helpers do
        alias Phoenix.HTML, as: PH
        def raw(input), do: Phoenix.HTML.raw(input)
        def qualified(input), do: PH.raw(input)
        def piped(input), do: input |> PH.raw()
        def captured(inputs), do: Enum.map(inputs, &PH.raw/1)
      end
      """)

    assert Enum.sort(Enum.map(results, & &1.vuln_line_no)) == [3, 4, 5, 6]
    assert Enum.sort(Enum.map(results, & &1.confidence)) == [:high, :high, :high, :medium]
  end

  test "a different local arity cannot hide an implicitly imported raw/1" do
    results =
      findings("""
      defmodule Helpers do
        use MyAppWeb, :html
        def direct(input), do: raw(input)
        def piped(input), do: input |> raw()
        def raw(input, options), do: byte_size(input)
      end
      """)

    assert Enum.sort(Enum.map(results, & &1.vuln_line_no)) == [3, 4]
  end

  test "local definitions stay in their module while nested modules retain aliases" do
    results =
      findings("""
      defmodule Parent do
        alias Phoenix.HTML, as: PH
        def raw(input), do: 42
        def local(input), do: raw(input)
        defmodule Child do
          def unsafe(input), do: raw(input)
          def qualified(input), do: PH.raw(input)
        end
      end
      defmodule Sibling do
        def unsafe(input), do: raw(input)
      end
      """)

    assert Enum.sort(Enum.map(results, & &1.vuln_line_no)) == [6, 7, 11]
  end

  test "inline HEEx uses its module's local raw binding" do
    results =
      findings(~S"""
      defmodule Component do
        def raw(input), do: input
        def render(assigns), do: ~H"{raw(@name)} {Phoenix.HTML.raw(@name)}"
      end
      """)

    assert [%Finding{vuln_line_no: 3, vuln_variable: "@name"}] = results
    assert Macro.to_string(hd(results).vuln_source) =~ "Phoenix.HTML.raw"
  end

  test "bare calls remain conservative without module context" do
    ast = Code.string_to_quoted!("def unsafe(input), do: raw(input)")
    assert {[_], _, _} = Raw.parse_raw_def(ast)
  end

  test "an explicit import of another raw helper is not a Phoenix call" do
    assert [%Finding{fun_name: :local_import}] =
             findings("""
             defmodule Helpers do
               import OtherHelpers, only: [raw: 1]
               def direct(input), do: raw(input)
               def piped(input), do: input |> raw()
               def captured(inputs), do: Enum.map(inputs, &raw/1)
               def local_import(input) do
                 import Phoenix.HTML, only: [raw: 1]
                 Phoenix.HTML.raw(input)
               end
             end
             """)
  end

  test "unresolved raw macros and delegates remain possible sinks" do
    for definition <- [
          "defmacro raw(input), do: quote(do: Phoenix.HTML.raw(unquote(input)))",
          "defdelegate raw(input), to: Phoenix.HTML"
        ] do
      assert [%Finding{fun_name: :unsafe}] =
               findings("""
               defmodule Helpers do
                 #{definition}
                 def unsafe(input), do: raw(input)
               end
               """)
    end
  end

  test "a local raw helper returning unsafe HTML retains the caller's original finding" do
    for body <- ["{:safe, input}", "Phoenix.HTML.raw(input)"] do
      results =
        findings("""
        defmodule Helpers do
          def unsafe(input), do: raw(input)
          def raw(input), do: #{body}
        end
        """)

      assert [%Finding{vuln_line_no: 2, confidence: :high} = caller] =
               Enum.filter(results, &(&1.fun_name == :unsafe))

      assert Macro.to_string(caller.vuln_source) == "raw(input)"
    end
  end

  test "an unsafe implementation cannot borrow safety from a default declaration or another clause" do
    for implementation <- [
          ~S"""
          def raw(input, options \\ [])
          def raw(input, _options), do: {:safe, input}
          """,
          """
          def raw(input) when is_binary(input), do: {:safe, input}
          def raw(_input), do: 42
          """
        ] do
      assert [%Finding{vuln_line_no: 2}] =
               findings("""
               defmodule Helpers do
                 def unsafe(input), do: raw(input)
                 #{implementation}
               end
               """)
    end
  end

  defp findings(source) do
    source
    |> Code.string_to_quoted!(columns: true)
    |> Lexical.functions()
    |> Enum.flat_map(fn {fun, context} ->
      Lexical.with_context(context, fn ->
        FunctionAnalysis.with_fun(fun, fn ->
          Finding.multi_from_def(%Finding{}, fun, Raw.parse_raw_def(fun))
        end)
      end)
    end)
  end
end
