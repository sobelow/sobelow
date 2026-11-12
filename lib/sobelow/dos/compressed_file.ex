defmodule Sobelow.DOS.CompressedFile do
  @moduledoc """
  # Potential resource exhaustion in full compressed-file reads

  Files opened with `:compressed` or `:compressed_one` decompress while reading.
  `IO.read/2` and `IO.binread/2` with `:all` or `:eof` can materialize the entire
  expanded contents. A small on-disk file or an output-size check after reading
  does not establish a decompressed-byte budget. `:eof` requires Elixir 1.13+.

  This check connects dynamic paths in `File.open/2`, `File.open!/2` and
  `:file.open/2` assignments, including piped opens, to subsequent full reads of
  the same variable. It also covers inline one-argument callbacks in
  `File.open/3` and `open!/3`.
  Read calls are the finding locations; labels refer to the original path.
  Controller paths receive medium confidence and other paths low confidence.

  Tracking is local and straight-line: reassignment, close, handle escape and
  branching/nested scopes stop tracking. Handle aliases, delegated callbacks,
  computed modes, indirect open expressions and literal paths are not tracked.
  Literal paths can still contain hostile data. Opening alone and fixed-size
  reads are omitted, not certified safe: repeated reads or a single huge line
  may still exhaust resources. Raw descriptors are not IO devices.

  Read bounded chunks while enforcing a cumulative actual-output budget before
  accumulation. Also bound input, execution resources and concurrency; closing
  a file automatically after the callback does not limit allocations within it.

  Ignore this check with:

      $ mix sobelow -i DOS.CompressedFile
  """
  @uid 50
  @finding_type "DOS.CompressedFile: Potential Resource Exhaustion in Compressed File Read"

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

  def parse_def(fun) do
    {params, declaration} = Parse.get_fun_declaration(fun)
    {Parse.compressed_file_findings(fun), params, declaration}
  end
end
