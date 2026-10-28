defmodule SobelowTest.E2E.SecurityAdditionsTest do
  use Sobelow.ScanCase, async: false

  @checks ["DOS.ModuleConcat", "RCE.Compile", "Crypto.WeakSignature", "Config.WeakTLS"]

  test "new rules have unique IDs and source-sensitive persisted skips" do
    source = """
    defmodule SecurityAdditions do
      def atoms(input), do: Module.concat(App, input)
      def compile(input), do: Code.compile_string(input)
      def signature(data, key), do: :public_key.sign(data, :sha, key)
      def tls(host), do: :ssl.connect(host, 443, versions: [:tlsv1])
    end
    """

    path = temp_fixture_file("basic", "lib/security_additions.ex", source)
    skips = temp_fixture_file("basic", ".sobelow-skips", "")
    report = scan("basic", only: @checks, mark_skip_all: true)
    assert finding_modules(report) == Enum.sort(@checks)
    assert length(File.read!(skips) |> String.split("\n", trim: true)) == 4
    assert scan("basic", only: @checks, skip: true)["total_findings"] == 0

    changed =
      source
      |> String.replace("Module.concat(App", "Module.concat(Other")
      |> String.replace("Code.compile_string(input)", "Code.compile_quoted(input)")
      |> String.replace(":sha, key", ":md5, key")
      |> String.replace("versions: [:tlsv1]", "versions: [:tlsv1, :\"tlsv1.1\"]")

    File.write!(path, changed)
    assert finding_modules(scan("basic", only: @checks, skip: true)) == Enum.sort(@checks)

    ids = Enum.map(Sobelow.finding_modules(), & &1.id())
    assert length(Enum.uniq(ids)) == length(ids)

    for {check, id} <- Enum.zip(@checks, ["SBLW042", "SBLW043", "SBLW044", "SBLW045"]) do
      assert apply(Sobelow.get_mod(check), :id, []) == id
    end
  end
end
