defmodule Sobelow.DynamicInputsTest do
  use Sobelow.ScanCase, async: false

  test "dynamic sigils and qualified or imported piped captures produce findings" do
    temp_fixture_file("basic", "lib/dynamic_inputs.ex", ~S'''
    defmodule DynamicInputs do
      import :os, only: [cmd: 1]
      def sigil(input), do: String.to_atom(~s(prefix_#{input}))
      def qualified(inputs), do: Enum.map(inputs, &(&1 |> :os.cmd()))
      def imported(inputs), do: Enum.map(inputs, &(&1 |> cmd()))
      def literal(), do: String.to_atom(~s(literal))
    end
    ''')

    report = scan("basic")
    assert [%{"line" => 3, "variable" => "input"}] = findings_for(report, "DOS.StringToAtom")

    assert [%{"line" => 4}, %{"line" => 5}] =
             report |> findings_for("CI.OS") |> Enum.sort_by(& &1["line"])

    temp_fixture_file("basic", ".sobelow-skips", "")
    scan_io("basic", mark_skip_all: true)
    skipped = scan("basic", skip: true)
    assert [] == findings_for(skipped, "DOS.StringToAtom")
    assert [] == findings_for(skipped, "CI.OS")
  end
end
