defmodule Sobelow.RCE.Compile do
  @moduledoc """
  # Code execution through compilation and loading

  `Code.compile_string/1,2` and `Code.compile_quoted/1,2` execute code while
  compiling it. `Code.compile_file/1,2` and `Code.require_file/1,2` compile
  and execute a source file; requiring a file only once does not make its
  contents trusted. Use these APIs only with trusted application code.

  Dynamic source and quoted expressions receive high confidence for direct
  controller parameters, medium for other controller values and low outside
  controllers. File selection receives medium confidence for controller
  parameters and low otherwise, since a dynamic path alone does not prove
  attacker control of file contents. Relative search roots are included;
  source filenames used only for diagnostics are not treated as code input.

  Fully literal inputs are omitted. Computed expressions and attributes are
  retained without resolving their values. Existing evaluation checks remain
  available separately as `RCE.CodeModule`.

  https://hexdocs.pm/elixir/Code.html#compile_string/2

      $ mix sobelow -i RCE.Compile
  """
  @uid 43
  @finding_type "RCE.Compile: Code Execution in Compilation or Loading"
  @file_functions [:compile_file, :require_file]
  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(fn finding ->
      confidence =
        if file_call?(finding.vuln_source),
          do: if(finding.confidence == :high, do: :medium, else: :low),
          else: finding.confidence

      Print.add_finding(%{finding | confidence: confidence})
    end)
  end

  # Source APIs: input index 0; index 1 is only a diagnostic filename.
  # File APIs: filename index 0, relative root index 1.
  def parse_def(fun) do
    {params, declaration} = Parse.get_fun_declaration(fun)

    source =
      for {call, _, [input | _]} <-
            Parse.calls_with_args(fun, [
              {[:Code], :compile_string, [1, 2]},
              {[:Code], :compile_quoted, [1, 2]}
            ]),
          variables = Parse.dynamic_vars(input),
          variables != [],
          do: {call, variables}

    files =
      Parse.file_selection_findings(
        fun,
        Enum.map(@file_functions, &{&1, [1, 2], 0, 1}),
        [:Code]
      )

    {source ++ files, params, declaration}
  end

  defp file_call?({:&, _, [{:/, _, [call, _arity]}]}), do: file_call?(call)
  defp file_call?({{:., _, [_, name]}, _, _}), do: name in @file_functions
  defp file_call?({name, _, _}), do: name in @file_functions
end
