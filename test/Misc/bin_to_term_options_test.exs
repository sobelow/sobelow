defmodule SobelowTest.Misc.BinToTermOptionsTest do
  use ExUnit.Case, async: true
  alias Sobelow.Misc.BinToTerm

  for call <- [
        "Plug.Crypto.non_executable_binary_to_term(data)",
        "Plug.Crypto.non_executable_binary_to_term(data, [])",
        "Plug.Crypto.non_executable_binary_to_term(data, opts)",
        "data |> Plug.Crypto.non_executable_binary_to_term()",
        "data |> Plug.Crypto.non_executable_binary_to_term(opts)",
        "Plug.Crypto.non_executable_binary_to_term(data, [safe: true])",
        "Plug.Crypto.non_executable_binary_to_term(data, [[:safe]])",
        "&Plug.Crypto.non_executable_binary_to_term/2",
        "&Plug.Crypto.non_executable_binary_to_term(&1)",
        ":erlang.binary_to_term(data, [:safe])",
        "data |> :erlang.binary_to_term([:safe])"
      ] do
    test "reports #{call}" do
      ast = Code.string_to_quoted!("def decode(data, opts), do: #{unquote(call)}")
      assert {[_], _, _} = BinToTerm.parse_def(ast)
    end
  end

  for call <- [
        "Plug.Crypto.non_executable_binary_to_term(data, [:safe])",
        "data |> Plug.Crypto.non_executable_binary_to_term([:used, :safe])",
        "&Plug.Crypto.non_executable_binary_to_term(&1, [:safe])",
        "Plug.Crypto.non_executable_binary_to_term(<<131, 97, 1>>)",
        "Other.non_executable_binary_to_term(data)",
        "non_executable_binary_to_term(data)"
      ] do
    test "omits #{call}" do
      ast = Code.string_to_quoted!("def decode(data), do: #{unquote(call)}")
      assert {[], _, _} = BinToTerm.parse_def(ast)
    end
  end
end
