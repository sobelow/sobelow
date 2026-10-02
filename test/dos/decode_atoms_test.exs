defmodule SobelowTest.DOS.DecodeAtomsTest do
  use ExUnit.Case, async: true
  alias Sobelow.DOS.DecodeAtoms

  for call <- [
        "Jason.decode(input, keys: :atoms)",
        "Jason.decode!(input, keys: :atoms)",
        "Jason.decode(input, keys: :strings, keys: :atoms)",
        "Poison.decode(input, %{keys: :atoms})",
        "Poison.decode!(input, keys: :atoms)",
        "input |> Jason.decode(keys: :atoms)",
        "input |> Poison.decode!(%{keys: :atoms})",
        "YamlElixir.read_from_string(input, atoms: true)",
        "YamlElixir.read_from_string!(input, atoms: true)",
        "YamlElixir.read_all_from_string(input, atoms: true)",
        "input |> YamlElixir.read_all_from_string!(atoms: true)",
        "Enum.map(input, &Jason.decode!(&1, keys: :atoms))"
      ] do
    test "detects #{call}" do
      ast = Code.string_to_quoted!("def decode(input), do: #{unquote(call)}")
      assert {[_], _, _} = DecodeAtoms.parse_def(ast)
    end
  end

  for call <- [
        "Jason.decode(input)",
        "Jason.decode(input, keys: :atoms!)",
        "Poison.decode!(input, %{keys: :atoms!})",
        "input |> Jason.decode!(keys: :strings)",
        "YamlElixir.read_from_string(input, atoms: false)",
        "Jason.decode(input, options)",
        "Jason.decode(input, keys: mode)",
        "Jason.decode(input, unrelated: [keys: :atoms])",
        "Jason.decode(keys: :atoms)",
        "Jason.decode(input, keys: :atoms, keys: :strings)",
        "Other.decode(input, keys: :atoms)",
        "decode(input, keys: :atoms)",
        "Jason.encode(input, keys: :atoms)",
        "Jason.decode(\"{}\", keys: :atoms)",
        "&Jason.decode/2"
      ] do
    test "does not report #{call}" do
      ast = Code.string_to_quoted!("def decode(input), do: #{unquote(call)}")
      assert {[], _, _} = DecodeAtoms.parse_def(ast)
    end
  end
end
