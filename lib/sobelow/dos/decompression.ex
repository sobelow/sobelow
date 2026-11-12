defmodule Sobelow.DOS.Decompression do
  @moduledoc """
  # Resource exhaustion through decompression

  `:zlib.gunzip/1`, `:zlib.uncompress/1`, `:zlib.unzip/1` and
  `:zlib.inflate/2,3` can expand untrusted compressed data without an
  application-defined output limit. Here `:zlib.unzip/1` decodes raw DEFLATE
  data, not a ZIP container; archive extraction is covered by `DOS.Zip`.
  Small compressed input or input chunks can produce much larger output.
  Checking output size after these calls may be too late to prevent exhaustion.

  Use bounded output chunks, for example with `:zlib.safeInflate/2`, while
  counting actual output bytes and stopping before a per-stream or cumulative
  budget is exceeded. Also bound compressed input, execution resources and
  concurrency. `safeInflate/2` bounds an individual call, not the whole stream;
  collecting all its output without a cumulative limit is still unbounded.
  Its presence elsewhere does not suppress findings for other decompression.

  This check reports dynamic compressed inputs, at medium confidence for
  controller parameters and low confidence otherwise. Fully literal inputs
  are omitted. Stream state, input provenance and custom preflight validators
  are not tracked. Compression, initialization, cleanup and `safeInflate/2`
  are not reported. Audit bounded wrappers before skipping them.

  https://www.erlang.org/doc/apps/erts/zlib.html

  Ignore this check with:

      $ mix sobelow -i DOS.Decompression
  """
  @uid 47
  @finding_type "DOS.Decompression: Potential Resource Exhaustion in Decompression"
  @calls [
    {:zlib, :gunzip, [1]},
    {:zlib, :uncompress, [1]},
    {:zlib, :unzip, [1]},
    {:zlib, :inflate, [2, 3]}
  ]

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

  # gunzip(data), uncompress(data), unzip(data): input index 0.
  # inflate(stream, data, options): input index 1; stream and options are not data.
  def parse_def(fun) do
    {params, declaration} = Parse.get_fun_declaration(fun)

    findings =
      for {call, name, args} <- Parse.calls_with_args(fun, @calls),
          input = Enum.at(args, if(name == :inflate, do: 1, else: 0)),
          variables = Parse.binary_input_vars(input),
          variables != [],
          do: {call, variables}

    {findings, params, declaration}
  end
end
