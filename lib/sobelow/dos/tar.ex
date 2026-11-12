defmodule Sobelow.DOS.Tar do
  @moduledoc """
  # Potential resource exhaustion in TAR extraction

  `:erl_tar.extract/1,2` can consume memory, disk space and execution resources
  when extracting untrusted archives. Compressed input and sparse entries can
  amplify resource use. Selected files, disk write chunks and post-extraction
  checks do not establish a cumulative expanded-byte budget.

  This check reports dynamic filenames, binary archives and archive handles.
  Controller parameters receive medium confidence; other inputs receive low
  confidence. Fully literal inputs and metadata/creation APIs are omitted.
  Literal paths can still refer to untrusted content. This is not a path
  traversal check and does not establish exploitability or input provenance.

  Use runtime-supported cumulative extraction limits, plus limits on entry
  count, input, concurrency and execution resources. OTP 29 adds `:max_size`;
  it is not a portable protection on older supported OTP releases. Consequently
  this check does not suppress calls based on that option or custom preflights.
  Audit bounded wrappers before applying a targeted skip.

  Ignore this check with:

      $ mix sobelow -i DOS.Tar
  """
  @uid 48
  @finding_type "DOS.Tar: Potential Resource Exhaustion in TAR Extraction"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(fn finding ->
      confidence = if finding.confidence == :high, do: :medium, else: :low
      Print.add_finding(%{finding | confidence: confidence})
    end)
  end

  # extract(archive, options): archive filename, {:binary, data} or handle at index 0.
  def parse_def(fun) do
    {params, declaration} = Parse.get_fun_declaration(fun)

    findings =
      for {call, :extract, [input | _]} <-
            Parse.calls_with_args(fun, [{:erl_tar, :extract, [1, 2]}]),
          variables = Parse.binary_input_vars(input),
          variables != [],
          do: {call, variables}

    {findings, params, declaration}
  end
end
