defmodule Sobelow.Crypto.WeakSignature do
  @moduledoc """
  # Weak digests in digital signatures

  MD5 and SHA-1 lack the collision resistance required for new digital
  signatures. Prefer a modern signature scheme and an appropriate digest
  such as SHA-256 or stronger. HMAC is a different construction and is not
  classified by this check.

  Literal `:md5` and `:sha` selections in `:crypto.sign/4,5`, `verify/5,6`,
  `:public_key.sign/3,4` and `verify/4,5` receive high confidence regardless
  of input taint. Verification may be needed for historical data; review the
  protocol before removing legacy support. Dynamic digest values are not
  resolved. Keys, padding and signature parameters are not validated.

  https://www.rfc-editor.org/rfc/rfc6151
  https://csrc.nist.gov/projects/hash-functions

      $ mix sobelow -i Crypto.WeakSignature
  """
  @uid 44
  @finding_type "Crypto.WeakSignature: Weak Digest in Digital Signature"
  @calls [
    {:crypto, :sign, [4, 5]},
    {:crypto, :verify, [5, 6]},
    {:public_key, :sign, [3, 4]},
    {:public_key, :verify, [4, 5]}
  ]
  use Sobelow.Finding

  def run(fun, meta_file) do
    fun |> parse_def() |> Sobelow.Crypto.add_findings(fun, meta_file, @finding_type)
  end

  # Every supported API takes the digest at index 1.
  def parse_def(fun) do
    for {call, _, [_, digest | _]} <- Parse.calls_with_args(fun, @calls),
        digest in [:md5, :sha],
        do: {call, digest, :high}
  end
end
