defmodule Sobelow.DOS.BinToAtom do
  @moduledoc """
  # Denial of Service via Unsafe Atom Interpolation

  In Elixir, atoms are not garbage collected. As such, if user input
  is used to create atoms (as in `:"foo\#{bar}"`, or in `:erlang.binary_to_atom`),
  it may result in memory exhaustion. Prefer the `String.to_existing_atom`
  function for untrusted user input.

  This also reports interpolated atom word sigils such as `~w(foo\#{bar})a`.
  Literal word lists, uppercase `~W` sigils, and string/charlist word sigils
  are omitted. Interpolated values are not evaluated or resolved.

  Atom interpolation checks can be ignored with the following command:

      $ mix sobelow -i DOS.BinToAtom
  """
  @uid 11
  @finding_type "DOS.BinToAtom: Unsafe atom interpolation"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    {calls, params, declaration} =
      Parse.get_erlang_fun_vars_and_meta(fun, 0, :binary_to_atom, :erlang)

    {calls ++ Parse.atom_sigil_findings(fun), params, declaration}
  end
end
