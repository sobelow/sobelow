defmodule Sobelow.DOS.Regex do
  @moduledoc """
  # Potential resource risk in dynamic regex compilation

  Compiling an attacker-influenced pattern can impose compilation costs and
  allow expensive matching behavior when the result is later used. This check
  reports dynamic patterns passed to `Regex.compile/1,2`, `compile!/1,2` and
  `:re.compile/1,2`. Controller pattern parameters receive medium confidence;
  other dynamic patterns receive low confidence. A finding does not demonstrate
  pathological runtime or prove that the pattern is untrusted or later matched.

  When input is meant as literal text, use `Regex.escape/1`, or avoid regexes.
  Direct escaped input and compositions containing only literal text and direct
  escaped values are omitted. Escaping prevents pattern syntax injection; it
  does not bound input size or total compilation/matching work. Escaped aliases
  and custom wrappers are not inferred. Literal patterns and direct escape
  calls are recognized without evaluating source ASTs.

  Dynamic patterns and fixed pathological patterns are distinct concerns. This
  initial rule does not analyze fixed-pattern complexity, matching calls,
  precompiled patterns, interpolated regex sigils, or pattern/subject trust
  across function boundaries. An omitted match is not certified safe.

  Bound pattern and subject sizes, compilation frequency, concurrency and
  execution resources. Use runtime-supported matching limits where appropriate,
  and handle limit errors; their semantics vary across engines and versions and
  they do not replace a compilation budget. A nearby timeout is not assumed to
  cancel work. Do not regard any particular fixed pattern as safe solely because
  it is not reported by this intentionally narrow check.

  Ignore this check with:

      $ mix sobelow -i DOS.Regex
  """
  @uid 51
  @finding_type "DOS.Regex: Potential Resource Risk in Dynamic Regex Compilation"
  @calls [
    {[:Regex], :compile, [1, 2]},
    {[:Regex], :compile!, [1, 2]},
    {:re, :compile, [1, 2]}
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

  # compile(pattern, options): pattern at index 0, not matching subject/options.
  def parse_def(fun) do
    {params, declaration} = Parse.get_fun_declaration(fun)

    findings =
      for {call, _, [pattern | _]} <- Parse.calls_with_args(fun, @calls),
          variables = Parse.unescaped_regex_vars(fun, pattern),
          variables != [],
          do: {call, variables}

    {findings, params, declaration}
  end
end
