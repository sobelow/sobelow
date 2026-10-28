defmodule SobelowTest.E2E.WeakSignatureTest do
  use Sobelow.ScanCase, async: false

  test "resolves Erlang imports, includes literal data and honors skips and renderers" do
    temp_fixture_file("basic", "lib/signatures.ex", """
    defmodule Signatures do
      import :public_key, only: [sign: 3]
      def literal(key), do: :crypto.sign(:rsa, :sha, "literal", key)
      def pipe(data, key), do: data |> sign(:md5, key)
      def verify(data, signature, key), do: :public_key.verify(data, :sha, signature, key)
      # sobelow_skip ["Crypto.WeakSignature"]
      def skipped(data, key), do: :crypto.sign(:rsa, :md5, data, key)
      def safe(data, key), do: :public_key.sign(data, :sha256, key)
    end
    """)

    found =
      scan("basic", only: ["Crypto.WeakSignature"], skip: true)
      |> findings_for("Crypto.WeakSignature")

    assert Enum.sort(Enum.map(found, & &1["line"])) == [3, 4, 5]
    assert Enum.all?(found, &(&1["confidence"] == "high"))
    assert [] = scan("basic", ignored: ["Crypto"]) |> findings_for("Crypto.WeakSignature")

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["Crypto.WeakSignature"], format: format)
      assert output =~ if(format == "sarif", do: "SBLW044", else: "Crypto.WeakSignature")
    end
  end

  test "excluded signature imports do not match unrelated functions" do
    temp_fixture_file("basic", "lib/unrelated_signatures.ex", """
    defmodule UnrelatedSignatures do
      import :crypto, except: [sign: 4]
      import Other, only: [verify: 4]
      def excluded(data, key), do: :rsa |> sign(:sha, data, key)
      def unrelated(data, key), do: verify(data, :sha, signature, key)
    end
    """)

    assert [] =
             scan("basic", only: ["Crypto.WeakSignature"]) |> findings_for("Crypto.WeakSignature")
  end
end
