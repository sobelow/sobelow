defmodule SobelowTest.DOS.AtomSigilTest do
  use ExUnit.Case, async: true
  alias Sobelow.DOS.BinToAtom

  for source <- [~S'~w(#{input})a', ~S'~w(prefix_#{input} fixed)a', ~S'~w(#{load()})a'] do
    test "reports #{source}" do
      ast = Code.string_to_quoted!("def run(input), do: #{unquote(source)}")
      assert {[{{:sigil_w, _, _}, _}], _, _} = BinToAtom.parse_def(ast)
    end
  end

  for source <- [~S'~w(fixed words)a', ~S'~W(#{input})a', ~S'~w(#{input})', ~S'~w(#{input})c'] do
    test "omits #{source}" do
      ast = Code.string_to_quoted!("def run(input), do: #{unquote(source)}")
      assert {[], _, _} = BinToAtom.parse_def(ast)
    end
  end

  test "ordinary atom interpolation retains its original source and fingerprint inputs" do
    ast = Code.string_to_quoted!(~S'def run(input), do: :"prefix_#{input}"', columns: true)
    old = Sobelow.Parse.get_erlang_fun_vars_and_meta(ast, 0, :binary_to_atom, :erlang)
    assert BinToAtom.parse_def(ast) == old
  end
end
