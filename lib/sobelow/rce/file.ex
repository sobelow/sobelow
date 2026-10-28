defmodule Sobelow.RCE.File do
  @moduledoc """
  # Code execution through Erlang files

  :file.eval/1,2, :file.script/1,2, :file.path_eval/2 and
  :file.path_script/2,3 read and execute Erlang expressions from a file.
  Only execute trusted application files. Avoid selecting executable files
  using request input, uploaded files or attacker-writable directories.

  Dynamic filenames and search directories receive medium confidence when
  they refer to controller parameters, and low confidence otherwise. A
  dynamic path does not prove attacker control over the file's contents.
  Bare function captures receive low confidence because their arguments
  and eventual invocation are unknown. Each call produces at most one finding.

  Fully literal file selections are omitted. An absolute literal filename
  ignores search directories, using the scanning host's path semantics.
  Fixed paths can still contain untrusted data: this check does not trace
  file writes, validate permissions, resolve dynamic paths or analyze the
  contents of scripts. Bindings are not treated as filenames.

  Unlike :file.consult, these functions execute expressions rather than
  merely reading terms.

  https://www.erlang.org/doc/apps/kernel/file.html#eval/1

      $ mix sobelow -i RCE.File
  """
  @uid 41
  @finding_type "RCE.File: Code Execution in Erlang File Evaluation"

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

  # eval/script(filename, bindings \\ []): filename index 0.
  # path_eval/path_script(directories, filename, ...): indexes 0 and 1.
  def parse_def(fun) do
    {params, declaration} = Parse.get_fun_declaration(fun)

    findings =
      Parse.file_selection_findings(fun, [
        {:eval, [1, 2], 0, nil},
        {:script, [1, 2], 0, nil},
        {:path_eval, [2], 1, 0},
        {:path_script, [2, 3], 1, 0}
      ])

    {findings, params, declaration}
  end
end
