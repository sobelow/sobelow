defmodule Sobelow.Crypto.WeakCipher do
  @moduledoc """
  # Weak ciphers and unauthenticated encryption

  DES, 3DES, RC2, RC4, Blowfish and ECB modes receive high confidence.
  Prefer authenticated encryption such as AES-GCM or ChaCha20-Poly1305.

  AES CBC, CTR, CFB and OFB modes, and raw ChaCha20, receive low confidence:
  these primitives do not authenticate ciphertext on their own. A separate,
  correctly composed MAC may make their use appropriate. The presence of
  an HMAC elsewhere in a function does not prove that composition and does
  not suppress the finding. Decryption calls are included for legacy data.

  This check inspects literal algorithm atoms in one-shot, streaming and
  legacy APIs. It does not resolve algorithms stored in variables, inspect
  keys or IVs, or validate the surrounding protocol.

  https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

      $ mix sobelow -i Crypto.WeakCipher
  """
  @uid 39
  @finding_type "Crypto.WeakCipher: Weak Cipher or Unauthenticated Encryption"
  @calls [
    {:crypto, :crypto_one_time, [4, 5]},
    {:crypto, :crypto_init, [3, 4]},
    {:crypto, :block_encrypt, [3, 4]},
    {:crypto, :block_decrypt, [3, 4]},
    {:crypto, :stream_init, [2, 3]}
  ]
  use Sobelow.Finding

  def run(fun, meta_file) do
    fun |> parse_def() |> Sobelow.Crypto.add_findings(fun, meta_file, @finding_type)
  end

  # All supported APIs take the cipher at index 0.
  def parse_def(fun) do
    for {call, _, [algorithm | _]} <- Parse.calls_with_args(fun, @calls),
        confidence <- [confidence(algorithm)],
        confidence,
        do: {call, algorithm, confidence}
  end

  defp confidence(algorithm) when is_atom(algorithm) do
    name = Atom.to_string(algorithm)

    cond do
      String.starts_with?(name, ["des_", "des3_", "rc2_", "blowfish_"]) or
        algorithm in [:des, :des3, :rc2, :rc4, :blowfish] or
          String.ends_with?(name, "_ecb") ->
        :high

      Regex.match?(~r/^aes_(?:(?:128|192|256)_)?(?:cbc|ctr|cfb8|cfb128|ofb)(?:128|256)?$/, name) or
          algorithm == :chacha20 ->
        :low

      true ->
        nil
    end
  end

  defp confidence(_), do: nil
end
