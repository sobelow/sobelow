defmodule Sobelow.DOS.DecodeAtoms do
  @moduledoc """
  # Atom exhaustion through decoders

  Jason and Poison can create new atoms with `keys: :atoms`. YamlElixir's
  string readers can create atoms with `atoms: true`. Decoding untrusted
  input with these options can exhaust the VM's atom table because atoms
  are not garbage collected.

  Prefer string keys, or `keys: :atoms!` in JSON decoders when only existing
  atoms are needed. Leave YamlElixir's atom conversion disabled for untrusted
  input. This check inspects literal options and dynamic decoder input;
  options built in variables or helper functions are not resolved.

  DecodeAtoms checks can be ignored with:

      $ mix sobelow -i DOS.DecodeAtoms
  """
  @uid 36
  @finding_type "DOS.DecodeAtoms: Atom Creation in Decoder"
  @decoders [
    {[:Jason], [:decode, :decode!], :keys, :atoms},
    {[:Poison], [:decode, :decode!], :keys, :atoms},
    {[:YamlElixir],
     [:read_from_string, :read_from_string!, :read_all_from_string, :read_all_from_string!],
     :atoms, true}
  ]

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  # All supported decoders take (input, options): input index 0, options index 1.
  def parse_def(fun) do
    {params, declaration} = Parse.get_fun_declaration(fun)
    piped = fun |> Parse.get_pipe_funs() |> Enum.map(fn {:|>, _, [_, call]} -> call end)

    findings =
      Enum.flat_map(@decoders, fn {module, functions, key, value} ->
        Enum.flat_map(functions, fn function ->
          {calls, _, _} = Parse.get_fun_vars_and_meta(fun, 0, function, module)

          Enum.filter(calls, fn {call, _variables} ->
            unsafe_options?(call, call in piped, key, value)
          end)
        end)
      end)

    {findings, params, declaration}
  end

  defp unsafe_options?({_, _, args}, piped?, key, value) when is_list(args) do
    arity = if piped?, do: 1, else: 2
    length(args) == arity and option(List.last(args), key) == {:ok, value}
  end

  defp unsafe_options?(_, _, _, _), do: false

  # JSON decoders normalize options to maps, so the last duplicate wins.
  defp option({:%{}, _, pairs}, :keys), do: option(pairs, :keys)

  defp option(options, key) when is_list(options) do
    options = if key == :keys, do: Enum.reverse(options), else: options
    if Keyword.keyword?(options), do: Keyword.fetch(options, key), else: :error
  end

  defp option(_, _), do: :error
end
