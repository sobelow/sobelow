defmodule SobelowTest.E2E.BinToTermTest do
  use Sobelow.ScanCase, async: false

  test "grades decoder protections and preserves historical Erlang fingerprints" do
    temp_fixture_file("basic", "lib/term_decoder.ex", """
    defmodule TermDecoder do
      def plain(data), do: :erlang.binary_to_term(data)
      def safe(data), do: :erlang.binary_to_term(data, [:safe])
      def piped(data), do: data |> :erlang.binary_to_term([:used, :safe])
      def unknown(data, opts), do: :erlang.binary_to_term(data, opts)
      def executable(data), do: Plug.Crypto.non_executable_binary_to_term(data)
      def protected(data), do: Plug.Crypto.non_executable_binary_to_term(data, [:safe])
      def protected_pipe(data), do: data |> Plug.Crypto.non_executable_binary_to_term([:safe, :used])
      def unknown_plug(data, opts), do: Plug.Crypto.non_executable_binary_to_term(data, opts)
      def no_safe(data), do: Plug.Crypto.non_executable_binary_to_term(data, [:used])
    end
    """)

    found = scan("basic") |> findings_for("Misc.BinToTerm")
    assert Enum.frequencies_by(found, & &1["confidence"]) == %{"high" => 5, "medium" => 2}
    assert Enum.sort(Enum.map(found, & &1["line"])) == [2, 3, 4, 5, 6, 9, 10]

    Sobelow.FindingLog.log()
    |> Map.values()
    |> List.flatten()
    |> Enum.each(fn {_details, finding, _} ->
      if finding.type == "Misc.BinToTerm: Unsafe `binary_to_term`" and
           finding.vuln_line_no in 2..5 do
        historical =
          Sobelow.Parse.get_erlang_fun_vars_and_meta(
            finding.fun_source,
            0,
            :binary_to_term,
            :erlang
          )

        [old] =
          Sobelow.Finding.init(finding.type, finding.filename, :high)
          |> Sobelow.Finding.multi_from_def(finding.fun_source, historical)

        assert Sobelow.Finding.fingerprint(old) == Sobelow.Finding.fingerprint(finding)

        assert Sobelow.Finding.legacy_fingerprint(old) ==
                 Sobelow.Finding.legacy_fingerprint(finding)
      end
    end)
  end

  test "resolves Plug aliases and imports while retaining safe pipe suppression" do
    temp_fixture_file("basic", "lib/term_decoder.ex", """
    defmodule TermDecoder do
      alias Plug.Crypto, as: Crypto
      import Plug.Crypto, only: [non_executable_binary_to_term: 2]
      def unsafe(data), do: Crypto.non_executable_binary_to_term(data)
      def imported(data), do: non_executable_binary_to_term(data, [])
      def pipe(data), do: data |> non_executable_binary_to_term([:safe])
      def alias_pipe(data), do: data |> Crypto.non_executable_binary_to_term([:safe])
      def unrelated(data), do: Other.non_executable_binary_to_term(data)
    end
    """)

    found = scan("basic") |> findings_for("Misc.BinToTerm")
    assert Enum.sort(Enum.map(found, & &1["line"])) == [4, 5]
    assert [] = scan("basic", ignored: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
  end

  test "confidence threshold, skips and SARIF retain their normal behavior" do
    temp_fixture_file("basic", "lib/term_decoder.ex", """
    defmodule TermDecoder do
      # sobelow_skip ["Misc.BinToTerm"]
      def skipped(data), do: Plug.Crypto.non_executable_binary_to_term(data)
      def safe(data), do: :erlang.binary_to_term(data, [:safe])
    end
    """)

    assert [%{"confidence" => "medium"}] =
             scan("basic", skip: true) |> findings_for("Misc.BinToTerm")

    assert [] = scan("basic", skip: true, threshold: :high) |> findings_for("Misc.BinToTerm")
    {output, _} = scan_io("basic", skip: true, format: "sarif")
    [run] = Jason.decode!(output)["runs"]
    assert Enum.count(run["results"], &(&1["ruleId"] == "SBLW014")) == 1
  end
end
