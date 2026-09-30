defmodule Sobelow.FindingCollectionTest do
  use ExUnit.Case, async: false
  alias Sobelow.{Finding, FindingLog, Fingerprint, FunctionAnalysis}

  setup do
    {:ok, _} = FindingLog.start_link()
    {:ok, _} = Fingerprint.start_link()
    :ok
  end

  test "batches retain full sources, custom metadata, counts and stable ordering" do
    source = Code.string_to_quoted!("def read(path), do: File.read(path)")

    findings =
      for line <- [3, 1, 2],
          do: %Finding{
            type: "Traversal.FileModule: test",
            filename: "file.ex",
            vuln_line_no: line,
            confidence: :low,
            fun_source: source,
            fingerprint: Integer.to_string(line)
          }

    FindingLog.with_batch(fn ->
      FunctionAnalysis.with_fun(source, fn ->
        for finding <- findings, do: FindingLog.add({finding.type, finding, ["custom"]}, :low)
      end)
    end)

    assert FindingLog.counts() == %{high: 0, medium: 0, low: 3}

    assert Enum.map(FindingLog.log().low, fn {_, finding, metadata} ->
             assert finding.fun_source == source
             assert metadata == ["custom"]
             finding.vuln_line_no
           end) == [1, 2, 3]

    assert FindingLog.log() == FindingLog.log()
    FindingLog.add({"later", %{hd(findings) | vuln_line_no: 0}, nil}, :high)
    assert FindingLog.counts() == %{high: 1, medium: 0, low: 3}
    assert length(FindingLog.log().high) == 1
  end

  test "nested batching flushes partial work on exceptions" do
    finding = %Finding{type: "test", filename: "file.ex", vuln_line_no: 1, confidence: :low}

    assert_raise RuntimeError, fn ->
      FindingLog.with_batch(fn ->
        FindingLog.with_batch(fn -> FindingLog.add({"test", finding, nil}, :low) end)
        raise "stop"
      end)
    end

    assert [{"test", ^finding, nil}] = FindingLog.log().low
  end

  test "fingerprint batches keep legacy membership and flush on exceptions" do
    Fingerprint.put_ignore("legacy")

    assert_raise RuntimeError, fn ->
      Fingerprint.with_batch(fn ->
        Fingerprint.put("new")
        Fingerprint.with_batch(fn -> Fingerprint.put("new") end)
        assert Fingerprint.member?("legacy")
        raise "stop"
      end)
    end

    assert Fingerprint.new_skips() == ["new"]
  end
end
