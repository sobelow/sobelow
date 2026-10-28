defmodule Sobelow.Misc.BinToTerm do
  @moduledoc """
  # Insecure use of `binary_to_term`

  Decoding untrusted Erlang terms without `:safe` can create atoms and
  exhaust VM resources. The `:safe` option prevents new atoms, but still
  permits executable terms. Decoding a function does not itself execute it;
  later application code may invoke it, including indirectly via protocols.

  Dynamic input to `:erlang.binary_to_term/1,2` is reported at high confidence,
  or medium when its options explicitly include `:safe`.
  `Plug.Crypto.non_executable_binary_to_term/1,2` rejects executable terms,
  but is still reported at high confidence unless `:safe` is also present.
  Computed options are not assumed safe. Confidence here reflects decoder
  protections; this check does not establish whether input is trusted.

  Prefer `Plug.Crypto.non_executable_binary_to_term(data, [:safe])` for
  untrusted ETF input, and validate the resulting types and structure.
  That combination is omitted by this check, but does not bound decoded
  size, decompression, or work performed on the resulting data.

  `binary_to_term` checks can be ignored with the following command:

      $ mix sobelow -i Misc.BinToTerm
  """
  @uid 14
  @finding_type "Misc.BinToTerm: Unsafe `binary_to_term`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    piped = piped_calls(fun)

    Finding.init(@finding_type, meta_file.filename, :high)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(fn finding ->
      finding =
        if finding.confidence != :low and safe_option?(finding.vuln_source, piped),
          do: %{finding | confidence: :medium},
          else: finding

      Print.add_finding(finding)
    end)
  end

  # Both decoders take (binary, options): input index 0, options index 1.
  def parse_def(fun) do
    {erlang, params, declaration} =
      Parse.get_erlang_fun_vars_and_meta(fun, 0, :binary_to_term, :erlang)

    {plug, _, _} =
      Parse.get_fun_vars_and_meta(fun, 0, :non_executable_binary_to_term, [:Plug, :Crypto])

    piped = piped_calls(fun)
    plug = Enum.reject(plug, fn {call, _vars} -> safe_option?(call, piped) end)
    {erlang ++ plug, params, declaration}
  end

  defp piped_calls(fun) do
    fun
    |> Parse.get_pipe_funs()
    |> Enum.map(fn {:|>, _, [_, call]} -> call end)
    |> MapSet.new()
  end

  defp safe_option?({_, _, args} = call, piped) when is_list(args) do
    index = if MapSet.member?(piped, call), do: 0, else: 1
    options = Enum.at(args, index)
    is_list(options) and :safe in options
  end

  defp safe_option?(_, _), do: false
end
