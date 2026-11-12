defmodule Sobelow.DOS.Zip do
  @moduledoc """
  # Resource exhaustion through ZIP extraction

  `:zip.unzip/1,2`, `:zip.extract/1,2` and `:zip.zip_get/1,2` can expand
  untrusted archives without a limit on actual output bytes. A single entry
  can exhaust memory, disk space or CPU; nested archives are not required.
  The `:memory`, `:file_list` and `:file_filter` options do not establish an
  expanded-byte limit. ZIP-declared sizes can be forged.

  Enforce per-entry and cumulative actual-output limits during bounded
  decompression, before allocating or writing the entire output. Also bound
  entry count, compressed input and execution resources. A size check after
  extraction is too late. A bounded preflight must inspect the same immutable
  archive data and byte ranges that subsequent extraction will consume.

  This check reports dynamic archive inputs and handles. Controller parameters
  influencing archive input receive medium confidence; other inputs and handles
  receive low confidence. Fully literal inputs are omitted, but a fixed filename
  can still contain untrusted data. Archive provenance and custom preflight
  validators are not verified. Metadata-only operations, archive creation and
  `:zip.foldl/3` are not covered. Audit bounded wrappers before skipping them.

  https://www.erlang.org/doc/apps/stdlib/zip.html

  Ignore this check with:

      $ mix sobelow -i DOS.Zip
  """
  @uid 46
  @finding_type "DOS.Zip: Potential Resource Exhaustion in ZIP Extraction"
  @archive_calls [{:zip, :unzip, [1, 2]}, {:zip, :extract, [1, 2]}]
  @handle_calls [{:zip, :zip_get, [1, 2]}]

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Enum.each([{@archive_calls, confidence}, {@handle_calls, :low}], fn {calls, confidence} ->
      Finding.init(@finding_type, meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, parse_calls(fun, calls))
      |> Enum.each(fn finding ->
        confidence = if finding.confidence == :high, do: :medium, else: :low
        Print.add_finding(%{finding | confidence: confidence})
      end)
    end)
  end

  # unzip(archive, options), extract(archive, options): input index 0.
  # zip_get(handle), zip_get(filename, handle): the handle is the last argument.
  def parse_def(fun), do: parse_calls(fun, @archive_calls ++ @handle_calls)

  defp parse_calls(fun, calls) do
    {params, declaration} = Parse.get_fun_declaration(fun)

    findings =
      for {call, name, args} <- Parse.calls_with_args(fun, calls),
          input = if(name == :zip_get, do: List.last(args), else: hd(args)),
          variables = Parse.binary_input_vars(input),
          variables != [],
          do: {call, variables}

    {findings, params, declaration}
  end
end
