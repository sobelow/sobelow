defmodule Sobelow.Crypto.WeakHash do
  @moduledoc """
  # Weak or inappropriate hashing

  MD4, MD5 and SHA-1 are unsuitable when collision resistance is required.
  RIPEMD-160 is reported as a legacy choice, not as a proven collision break.
  Prefer SHA-256 or stronger for security-sensitive digests. Non-security
  checksums and cache keys may legitimately use legacy hashes.

  Only the algorithm is inspected, never the names of the values being
  hashed, so a fast hash used for password storage is not reported.

  Legacy hashes receive medium confidence in controllers and low elsewhere.
  HMAC-MD5 receives low confidence as a legacy construction; HMAC-SHA1 is
  not flagged merely because unkeyed SHA-1 has collision attacks.
  Dynamic algorithm values are not resolved. Calls with literal data,
  inline captures and pipes are included.

  References:
  https://www.rfc-editor.org/rfc/rfc6151

      $ mix sobelow -i Crypto.WeakHash
  """
  @uid 38
  @finding_type "Crypto.WeakHash: Weak or Inappropriate Hash"
  @legacy [:md4, :md5, :sha, :ripemd160]
  @calls [
    {:crypto, :hash, [2]},
    {:crypto, :hash_init, [1]},
    {:erlang, :md5, [1]},
    {:erlang, :md5_init, [0]},
    {:crypto, :mac, [4]},
    {:crypto, :macN, [5]},
    {:crypto, :mac_init, [3]},
    {:crypto, :hmac, [3, 4]}
  ]
  use Sobelow.Finding

  def run(fun, meta_file) do
    legacy = if meta_file.controller?, do: :medium, else: :low
    fun |> parse_def(legacy) |> Sobelow.Crypto.add_findings(fun, meta_file, @finding_type)
  end

  # hash(algorithm, data), md5(data), hmac(algorithm, key, data);
  # mac(type, algorithm, key, data). Streaming initializers inspect algorithms only.
  # `legacy` is the confidence for legacy hashes, which depends on the module.
  def parse_def(fun, legacy \\ :low) do
    for {call, name, args} <- Parse.calls_with_args(fun, @calls),
        {reason, confidence} <- [classify(name, args, legacy)],
        do: {call, reason, confidence}
  end

  defp classify(:md5, [data], legacy), do: classify(:hash, [:md5, data], legacy)
  defp classify(:md5_init, [], legacy), do: {:md5, legacy}

  defp classify(name, [algorithm | _], legacy)
       when name in [:hash, :hash_init] and algorithm in @legacy,
       do: {algorithm, legacy}

  defp classify(:hmac, [:md5 | _], _), do: {"HMAC-MD5", :low}

  defp classify(name, [:hmac, :md5 | _], _) when name in [:mac, :macN, :mac_init],
    do: {"HMAC-MD5", :low}

  defp classify(_, _, _), do: nil
end
