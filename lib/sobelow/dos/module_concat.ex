defmodule Sobelow.DOS.ModuleConcat do
  @moduledoc """
  # Atom exhaustion through dynamic module names

  `Module.concat/1,2` creates module-name atoms. Unbounded names derived from
  request input can exhaust the VM's atom table, even if no module is loaded
  under those names. Atoms are not garbage collected.

  Prefer an explicit lookup of allowed module names. `Module.safe_concat/1,2`
  avoids creating new atoms, but still requires authorization of the module
  selected. Fully literal names are omitted. Computed names and attributes
  are retained; this check does not resolve their possible values.

  https://security.erlef.org/secure_coding_and_deployment_hardening/atom_exhaustion.html

      $ mix sobelow -i DOS.ModuleConcat
  """
  @uid 42
  @finding_type "DOS.ModuleConcat: Atom Creation in Dynamic Module Names"
  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding/1)
  end

  # concat(names) and concat(left, right): every argument contributes to the atom.
  def parse_def(fun) do
    {params, declaration} = Parse.get_fun_declaration(fun)

    findings =
      for {call, :concat, args} <- Parse.calls_with_args(fun, [{[:Module], :concat, [1, 2]}]),
          variables = args |> Enum.flat_map(&Parse.dynamic_vars/1) |> Enum.uniq(),
          variables != [],
          do: {call, variables}

    {findings, params, declaration}
  end
end
