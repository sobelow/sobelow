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
  When request-controlled input is decoded with both protections, this check
  also reports a directly forwarded term: a return or application consumer
  reached without extracting and checking its scalar shape. It follows local
  assignments, guarded clauses, and bounded statically resolvable helpers
  across selected project files, including literal module dispatch. It does
  not follow arbitrary dynamic calls or callbacks; when an analysis limit
  prevents a decision, it warns rather than treating the path as safe.
  A guarded scalar returned with a fixed rejection path is not considered a
  forwarded term. Absence of a finding does not assure bounded resource use. ETF
  supports compressed terms: neither `:safe` nor rejection of executable
  terms imposes a decompression or decoded-memory budget. Even uncompressed
  terms can allocate more memory than their encoded representation. A limit
  on encoded bytes alone may therefore be insufficient.

  Validate types and structure, but remember that validation after decoding
  cannot prevent allocations already made by the decoder. Bound input,
  concurrency and execution resources independently; for hostile inputs,
  consider an isolated decoding worker with externally enforced resource
  limits. No decoder option described here provides a hard cumulative resource
  budget, and subsequent processing of the decoded term needs its own limits.
  Confidence reflects decoder protections, not proof of resource safety.

  `binary_to_term` checks can be ignored with the following command:

      $ mix sobelow -i Misc.BinToTerm
  """
  @uid 14
  @finding_type "Misc.BinToTerm: Unsafe `binary_to_term`"

  use Sobelow.Finding

  @reported_key {__MODULE__, :reported_handoffs}

  # A file worker can reach the same decoder through several local callers.
  # Report one finding per decoder location, without changing other checks or
  # suppressing a later caller when the first one was skipped.
  @doc false
  def with_file(fun) do
    previous = Process.get(@reported_key)
    Process.put(@reported_key, MapSet.new())

    try do
      fun.()
    after
      Process.put(@reported_key, previous)
    end
  end

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

    if meta_file[:local_terms] do
      Parse.UncheckedTerms.handoffs(fun, meta_file.local_terms, meta_file.controller?)
      |> Enum.each(fn {node, origin, source, use_line} ->
        {params, declaration} = Parse.get_fun_declaration(origin)
        variable = "#{source}; unchecked handoff at line #{use_line}"

        Finding.init(@finding_type, meta_file.filename, :high)
        |> Finding.multi_from_def(origin, {[{node, variable}], params, declaration})
        |> Enum.each(&add_handoff/1)
      end)
    end
  end

  @doc false
  def project_handoffs(project) do
    reported =
      Sobelow.FindingLog.log()
      |> Map.values()
      |> List.flatten()
      |> Enum.reduce(MapSet.new(), fn {_details, finding, _meta}, acc ->
        MapSet.put(acc, finding.fingerprint)
      end)

    Parse.UncheckedTerms.project_handoffs(project)
    |> Enum.reduce(reported, fn {node, origin, source, use_line}, reported ->
      {params, declaration} = Parse.get_fun_declaration(origin.fun)
      variable = "#{source}; unchecked handoff at line #{use_line}"

      [finding] =
        Finding.init(@finding_type, origin.filename, :high)
        |> Finding.multi_from_def(origin.fun, {[{node, variable}], params, declaration})

      finding = Finding.fetch_fingerprint(finding)

      if MapSet.member?(reported, finding.fingerprint) or
           not Sobelow.loggable?(finding, finding.confidence) do
        reported
      else
        Print.add_finding(finding)
        MapSet.put(reported, finding.fingerprint)
      end
    end)
  end

  defp add_handoff(finding) do
    finding = Finding.fetch_fingerprint(finding)
    reported = Process.get(@reported_key, MapSet.new())

    if not MapSet.member?(reported, finding.fingerprint) and
         Sobelow.loggable?(finding, finding.confidence) do
      Process.put(@reported_key, MapSet.put(reported, finding.fingerprint))
      Print.add_finding(finding)
    end
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
