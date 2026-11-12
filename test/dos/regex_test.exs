defmodule SobelowTest.DOS.RegexTest do
  use ExUnit.Case, async: true
  alias Sobelow.DOS.Regex, as: RegexCheck

  for call <- [
        "Regex.compile(pattern)",
        "Regex.compile!(pattern, \"i\")",
        "pattern |> Regex.compile()",
        ":re.compile(pattern, [:unicode])",
        "&Regex.compile/1",
        "&:re.compile/2",
        "Regex.compile(\"^\" <> pattern <> \"$\")",
        "Regex.compile(Regex.escape(prefix) <> pattern)",
        "Regex.compile(Other.escape(pattern))",
        "Regex.compile(escaped_pattern)",
        ~S'Regex.compile("^#{pattern}$")'
      ] do
    test "reports dynamic pattern compilation #{call}" do
      ast = Code.string_to_quoted!("def compile(pattern), do: #{unquote(call)}")
      assert {[_], _, _} = RegexCheck.parse_def(ast)
    end
  end

  for call <- [
        "Regex.compile(\"^literal$\")",
        "Regex.compile(~S\"literal\", opts)",
        ":re.compile(~c\"literal\")",
        "Regex.compile(Regex.escape(pattern))",
        "Regex.compile(pattern |> Regex.escape())",
        "Regex.compile(\"^\" <> Regex.escape(pattern) <> \"$\")",
        ~S'Regex.compile("^#{Regex.escape(pattern)}$")',
        "Regex.compile(\"(a+)+$\")",
        "Regex.match?(~r/(a+)+$/, pattern)",
        ":re.run(subject, pattern)",
        "Other.compile(pattern)",
        "compile(pattern)",
        "Regex.compile()",
        "Regex.compile(pattern, [], extra)"
      ] do
    test "omits literal, escaped, matching or unrelated call #{call}" do
      ast = Code.string_to_quoted!("def compile(pattern), do: #{unquote(call)}")
      assert {[], _, _} = RegexCheck.parse_def(ast)
    end
  end

  test "does not count escaped inputs in a partially dynamic pattern" do
    ast =
      Code.string_to_quoted!(
        "def compile(pattern, prefix), do: Regex.compile(Regex.escape(prefix) <> pattern)"
      )

    assert {[{_, [:pattern]}], _, _} = RegexCheck.parse_def(ast)
  end

  test "bounded runtime example demonstrates escaping as literal text, not a work budget" do
    pattern = "(a+)+$"
    assert Regex.match?(Regex.compile!(Regex.escape(pattern)), pattern)
    refute Regex.match?(Regex.compile!(Regex.escape(pattern)), "aaaa!")
  end
end
