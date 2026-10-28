defmodule SobelowTest.CryptoTest do
  use ExUnit.Case, async: true
  alias Sobelow.Crypto.{WeakCipher, WeakHash}

  defp ast(body, name \\ "run"), do: Code.string_to_quoted!("def #{name}(data), do: (#{body})")

  for {source, confidence} <- [
        {":crypto.hash(:md5, data)", :low},
        {":crypto.hash(:sha, \"literal\")", :low},
        {":crypto.hash_init(:md4)", :low},
        {":crypto.hash(:ripemd160, data)", :low},
        {":md5 |> :crypto.hash(data)", :low},
        {":erlang.md5(data)", :low},
        {":erlang.md5_init()", :low},
        {"&:erlang.md5_init/0", :low},
        {"&:erlang.md5/1", :low},
        {"&:crypto.hash(:md5, &1)", :low},
        {":crypto.hash(:md5, user.password_hash)", :low},
        {":crypto.mac(:hmac, :md5, key, data)", :low},
        {":crypto.macN(:hmac, :md5, key, data, 8)", :low},
        {":crypto.mac_init(:hmac, :md5, key)", :low},
        {":crypto.hmac(:md5, key, data)", :low},
        {":crypto.hmac(:md5, key, data, 8)", :low}
      ] do
    test "hash: #{source}" do
      assert [{_, _, unquote(confidence)}] = WeakHash.parse_def(ast(unquote(source)))
    end
  end

  for source <- [
        ":crypto.hash(:sha256, data)",
        ":crypto.hash(:sha256, \"password\")",
        ":crypto.hash(:sha256, password)",
        ":crypto.hash(:sha512, params[\"password\"])",
        ":crypto.hash(:sha256, user.password)",
        ":crypto.hash(:sha256, bypass)",
        ":crypto.mac(:hmac, :sha, key, password)",
        ":crypto.hmac(:sha, key, data)",
        ":crypto.mac(:cmac, :aes_128_cbc, key, data)",
        ":crypto.hash(algorithm, data)",
        ":crypto.hash(:md5)",
        "Other.hash(:md5, data)",
        "&:crypto.hash/2"
      ] do
    test "safe/unresolved hash: #{source}" do
      assert [] = WeakHash.parse_def(ast(unquote(source)))
    end
  end

  for {source, confidence} <- [
        {":crypto.crypto_one_time(:aes_128_ecb, key, data, true)", :high},
        {":crypto.crypto_init(:des_ede3_cbc, key, iv, false)", :high},
        {":crypto.crypto_init(:rc4, key, true)", :high},
        {":crypto.block_encrypt(:blowfish_cbc, key, iv, data)", :high},
        {":crypto.block_decrypt(:des_cbc, key, iv, data)", :high},
        {":crypto.stream_init(:rc4, key)", :high},
        {":aes_256_ecb |> :crypto.crypto_one_time(key, data, true)", :high},
        {"&:crypto.crypto_one_time(:aes_128_ecb, key, &1, true)", :high},
        {":crypto.crypto_one_time(:aes_256_cbc, key, iv, data, true)", :low},
        {":crypto.crypto_init(:aes_ctr, key, iv, true)", :low},
        {":crypto.block_encrypt(:aes_cbc256, key, iv, data)", :low},
        {":crypto.crypto_one_time(:chacha20, key, iv, data, true)", :low}
      ] do
    test "cipher: #{source}" do
      assert [{_, _, unquote(confidence)}] = WeakCipher.parse_def(ast(unquote(source)))
    end
  end

  for source <- [
        ":crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, data, aad, true)",
        ":crypto.crypto_one_time_aead(:chacha20_poly1305, key, iv, data, aad, true)",
        ":crypto.crypto_one_time(cipher, key, iv, data, true)",
        ":crypto.crypto_init(:aes_128_ecb)",
        "Other.crypto_init(:aes_128_ecb, key, true)"
      ] do
    test "safe/unresolved cipher: #{source}" do
      assert [] = WeakCipher.parse_def(ast(unquote(source)))
    end
  end

  test "unrelated HMAC does not suppress unauthenticated encryption" do
    assert [{_, :aes_128_cbc, :low}] =
             WeakCipher.parse_def(
               ast("""
               :crypto.mac(:hmac, :sha256, key, unrelated)
               :crypto.crypto_one_time(:aes_128_cbc, key, iv, data, true)
               """)
             )
  end

  test "legacy hash confidence is supplied by the caller; HMAC-MD5 stays low" do
    assert [{_, :md5, :medium}] = WeakHash.parse_def(ast(":crypto.hash(:md5, data)"), :medium)
    assert [{_, _, :low}] = WeakHash.parse_def(ast(":crypto.hmac(:md5, key, data)"), :medium)
  end

  test "effective pipe arguments retain the original call and location" do
    fun = ast(":md5 |> :crypto.hash(data)")

    [{call, :hash, [:md5, {:data, _, nil}]}] =
      Sobelow.Parse.calls_with_args(fun, [{:crypto, :hash, [2]}])

    assert {{:., _, [:crypto, :hash]}, _, [{:data, _, nil}]} = call
    assert Sobelow.Parse.get_fun_line(call) == 1
  end

  test "pipes containing do blocks still supply the piped argument" do
    assert [{_, _, :low}] =
             WeakHash.parse_def(
               ast("data |> Enum.map(fn x -> if x do x end end) |> :erlang.md5()")
             )
  end
end
