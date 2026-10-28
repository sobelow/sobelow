defmodule Sobelow.DOS.Consult do
  @moduledoc """
  # Atom exhaustion through Erlang term files

  `:file.consult/1` and `:file.path_consult/2` parse Erlang terms from a
  text file. Untrusted contents can create arbitrary atoms and exhaust VM
  resources. These functions have no `:safe` option. They parse terms;
  they do not evaluate arbitrary expressions like `:file.eval/1`.

  This check reports dynamic filenames and search directories. Controller
  parameters influencing file selection receive medium confidence; other
  dynamic paths receive low confidence. A dynamic path does not establish
  that an attacker controls the file contents.

  Only consult trusted application files. Use a format and decoder that do
  not create atoms for uploaded or downloaded data. Fully literal paths are
  omitted, but a fixed path may still contain untrusted data. This check
  does not trace file writes or verify ownership and permissions.

  Ignore this check with:

      $ mix sobelow -i DOS.Consult
  """
  @uid 37
  @finding_type "DOS.Consult: Potential Atom Exhaustion in Erlang Term Files"

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

  # consult(filename): index 0.
  # path_consult(directories, filename): indexes 0 and 1 influence file selection.
  def parse_def(fun) do
    {params, declaration} = Parse.get_fun_declaration(fun)

    findings =
      Parse.file_selection_findings(fun, [
        {:consult, [1], 0, nil},
        {:path_consult, [2], 1, 0}
      ])

    {findings, params, declaration}
  end
end
