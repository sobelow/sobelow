defmodule Sobelow.DOS.XML do
  @moduledoc """
  # Potential resource exhaustion with explicit XML entity options

  Entity expansion can amplify XML processing work and memory. External resource
  loading is a separate concern: it can consume resources and, depending on the
  resolver and context, may also expose files or enable unwanted requests. This
  check does not establish file disclosure, SSRF or exploitability.

  This intentionally narrow check reports dynamic input to `:xmerl_scan.string/2`
  and `file/2` with explicit `allow_entities: true`, and to
  `:xmerl_sax_parser.stream/2` and `file/2` with explicit
  `external_entities: :all` or `:file`, or an `entity_recurse_limit` above 3.
  `:disallow_entities` suppresses the recursion warning, but is not treated as
  disabling external DTD loading. `:skip_external_dtd` alone does not disable
  internal entities or all external entities. For supported, valid options, the
  last duplicate value wins.

  Controller inputs receive medium confidence; other dynamic inputs receive
  low confidence. Literal inputs, computed option lists and default-only calls
  are omitted, not certified safe. Options and defaults differ across OTP
  versions; this check does not validate runtime support. Default recursion
  limits are not cumulative byte budgets. Custom resolvers, input provenance
  and runtime versions are not inferred.

  Disable unnecessary entities and external resolution using options supported
  by the deployed runtime. Older xmerl versions may reject protective options
  such as `:disallow_entities`; do not silently retry without protection.
  Bound XML input, output/work, concurrency and permitted external resources
  independently. Streaming alone is not a budget.
  Review custom resolution callbacks rather than assuming they are safe.

  Ignore this check with:

      $ mix sobelow -i DOS.XML
  """
  @uid 49
  @finding_type "DOS.XML: Potential Resource Exhaustion with XML Entities"
  @calls [
    {:xmerl_scan, :string, [2]},
    {:xmerl_scan, :file, [2]},
    {:xmerl_sax_parser, :stream, [2]},
    {:xmerl_sax_parser, :file, [2]}
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

  # string/stream/file(input, options): input at index 0, parser options at index 1.
  def parse_def(fun) do
    {params, declaration} = Parse.get_fun_declaration(fun)

    findings =
      for {module, name, arities} <- @calls,
          parser = if(module == :xmerl_scan, do: :scan, else: :sax),
          {call, _, [input, options]} <- Parse.calls_with_args(fun, [{module, name, arities}]),
          Parse.risky_xml_options?(parser, options),
          variables = Parse.binary_input_vars(input),
          variables != [],
          do: {call, variables}

    {findings, params, declaration}
  end
end
