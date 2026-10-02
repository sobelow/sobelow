defmodule SobelowTest.E2E.DecodeAtomsTest do
  use Sobelow.ScanCase, async: false

  test "resolves aliases and imports, grades confidence, and retains call locations" do
    temp_fixture_file("basic", "lib/basic_web/controllers/decode_controller.ex", """
    defmodule BasicWeb.DecodeController do
      use BasicWeb, :controller
      alias Jason, as: JSON
      import Poison, only: [decode!: 2]
      def create(conn, input) do
        JSON.decode(input, keys: :atoms)
        input |> decode!(keys: :atoms)
        YamlElixir.read_from_string(local_input(), atoms: true)
      end
    end
    """)

    temp_fixture_file("basic", "lib/decoder.ex", """
    defmodule Decoder do
      def decode(input), do: Jason.decode(input, keys: :atoms)
    end
    """)

    found = scan("basic") |> findings_for("DOS.DecodeAtoms")

    assert Enum.frequencies_by(found, & &1["confidence"]) == %{
             "high" => 2,
             "medium" => 1,
             "low" => 1
           }

    controller = Enum.filter(found, &String.ends_with?(&1["file"], "decode_controller.ex"))
    assert Enum.sort(Enum.map(controller, & &1["line"])) == [6, 7, 8]
  end

  test "does not flag unrelated imports or local decoder names" do
    temp_fixture_file("basic", "lib/decoder.ex", """
    defmodule Decoder do
      import Other, only: [decode!: 2]
      def run(input) do
        decode!(input, keys: :atoms)
        decode(input, keys: :atoms)
      end
      def decode(input, _opts), do: input
    end
    """)

    assert [] = scan("basic") |> findings_for("DOS.DecodeAtoms")
  end

  test "supports ignore, per-function skips, and SARIF registration" do
    temp_fixture_file("basic", "lib/decoder.ex", """
    defmodule Decoder do
      def decode(input), do: Jason.decode(input, keys: :atoms)
      # sobelow_skip [\"DOS.DecodeAtoms\"]
      def skipped(input), do: Poison.decode!(input, keys: :atoms)
    end
    """)

    assert [_, _] = scan("basic") |> findings_for("DOS.DecodeAtoms")
    assert [_] = scan("basic", skip: true) |> findings_for("DOS.DecodeAtoms")
    assert [] = scan("basic", ignored: ["DOS.DecodeAtoms"]) |> findings_for("DOS.DecodeAtoms")
    {output, _} = scan_io("basic", format: "sarif")
    [run] = Jason.decode!(output)["runs"]
    results = Enum.filter(run["results"], &(&1["ruleId"] == "SBLW036"))
    assert length(results) == 2
  end
end
