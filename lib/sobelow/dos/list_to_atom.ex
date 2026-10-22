defmodule Sobelow.DOS.ListToAtom do
  @moduledoc """
  # Denial of Service via `List.to_atom` and `:erlang.list_to_atom`

  In Elixir, atoms are not garbage collected. As such, if user input
  is passed to the `List.to_atom` function, or to its Erlang equivalent
  `:erlang.list_to_atom`, it may result in memory exhaustion. Prefer the
  `List.to_existing_atom` function for untrusted user input.

  `List.to_atom` and `:erlang.list_to_atom` checks can be ignored with the
  following command:

      $ mix sobelow -i DOS.ListToAtom
  """
  @uid 12
  @finding_type "DOS.ListToAtom: Unsafe `List.to_atom`"
  @erlang_finding_type "DOS.ListToAtom: Unsafe `:erlang.list_to_atom`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))

    Finding.init(@erlang_finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def_erlang(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  ## List.to_atom(list)
  def parse_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 0, :to_atom, [:List])
  end

  ## :erlang.list_to_atom(list)
  def parse_def_erlang(fun) do
    Parse.get_erlang_fun_vars_and_meta(fun, 0, :list_to_atom, :erlang)
  end
end
