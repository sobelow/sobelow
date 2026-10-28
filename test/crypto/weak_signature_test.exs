defmodule SobelowTest.Crypto.WeakSignatureTest do
  use ExUnit.Case, async: true
  alias Sobelow.Crypto.WeakSignature

  for source <- [
        ":crypto.sign(:rsa, :md5, data, key)",
        ":crypto.sign(:rsa, :sha, data, key, [])",
        ":crypto.verify(:rsa, :sha, data, signature, key)",
        ":crypto.verify(:rsa, :md5, data, signature, key, [])",
        ":public_key.sign(data, :sha, key)",
        ":public_key.sign(data, :md5, key, [])",
        ":public_key.verify(data, :sha, signature, key)",
        ":public_key.verify(data, :md5, signature, key, [])",
        ":rsa |> :crypto.sign(:sha, data, key)",
        "data |> :public_key.sign(:md5, key)",
        "&:crypto.sign(:rsa, :sha, &1, key)",
        ":public_key.sign(\"literal\", :md5, key)"
      ] do
    test "reports #{source}" do
      ast = Code.string_to_quoted!("def run(data), do: #{unquote(source)}")
      assert [{_, _, :high}] = WeakSignature.parse_def(ast)
    end
  end

  for source <- [
        ":crypto.sign(:rsa, :sha256, data, key)",
        ":public_key.sign(data, :sha512, key)",
        ":crypto.sign(:eddsa, :none, data, key)",
        ":crypto.sign(:rsa, digest, data, key)",
        ":crypto.mac(:hmac, :sha, key, data)",
        ":crypto.hash(:sha, data)",
        ":crypto.sign(:rsa, :sha, data)",
        ":public_key.sign(data, :sha)",
        "Other.sign(data, :sha, key)",
        "sign(data, :sha, key)",
        "&:crypto.sign/4"
      ] do
    test "omits #{source}" do
      ast = Code.string_to_quoted!("def run(data), do: #{unquote(source)}")
      assert [] = WeakSignature.parse_def(ast)
    end
  end
end
