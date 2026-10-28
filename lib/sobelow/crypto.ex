defmodule Sobelow.Crypto do
  @moduledoc """
  # Cryptography

  Checks literal hash and cipher algorithm choices. These checks do not
  prove that a cryptographic construction is secure.

      $ mix sobelow -d Crypto.WeakHash
      $ mix sobelow -d Crypto.WeakCipher
      $ mix sobelow -d Crypto.WeakSignature

  Ignore the category with:

      $ mix sobelow -i Crypto
  """
  @submodules [Sobelow.Crypto.WeakHash, Sobelow.Crypto.WeakCipher, Sobelow.Crypto.WeakSignature]
  use Sobelow.FindingType

  def get_vulns(fun, meta_file, _web_root, skip_mods \\ []) do
    __MODULE__
    |> Sobelow.allowed_checks(@submodules, skip_mods)
    |> Enum.each(& &1.run(fun, meta_file))
  end

  @doc false
  # Report each `{call, label, confidence}` from a check's `parse_def`.
  def add_findings(results, fun, meta_file, finding_type) do
    {params, declaration} = Sobelow.Parse.get_fun_declaration(fun)

    Enum.each(results, fn {call, label, confidence} ->
      Sobelow.Finding.init(finding_type, meta_file.filename, confidence)
      |> Sobelow.Finding.multi_from_def(fun, {[{call, label}], params, declaration})
      |> Enum.each(&Sobelow.Print.add_finding/1)
    end)
  end

  def details, do: @moduledoc
end
