defmodule Sobelow.XSS.Raw do
  @moduledoc """
  # XSS in `raw`

  This submodule checks for the use of `raw` in templates
  as this can lead to XSS vulnerabilities if taking user input.

  Recognized local helpers and explicit imports of unrelated `raw` functions
  are excluded. A local helper that returns dynamic `{:safe, value}` output or
  calls another `raw` function retains its caller's finding. Unresolved raw
  macros and delegates remain possible sinks.

  Raw checks can be ignored with the following command:

      $ mix sobelow -i XSS.Raw
  """
  @uid 30
  @finding_type "XSS.Raw: XSS"

  alias Sobelow.Parse.Calls
  alias Sobelow.Parse.Flow.LiveView
  alias Sobelow.Parse.Metadata

  use Sobelow.Finding

  def run(fun, meta_file, _, nil) do
    run_direct(fun, meta_file)
  end

  def run(fun, meta_file, _web_root, controller) do
    run_direct(fun, meta_file)

    {vars, _, {fun_name, line_no}} = parse_render_def(fun)
    filename = meta_file.filename

    base = %Finding{
      type: @finding_type,
      filename: filename,
      fun_source: fun,
      fun_name: fun_name,
      fun_line_no: line_no
    }

    paths =
      Enum.flat_map(vars, fn {_finding, {template, _refs, _vars}} ->
        template_paths(filename, controller, template_name(template))
      end)

    # Every render sees the same prepared evidence. Consuming raw expressions
    # here would make later correlations depend on worker order and filtering.
    templates = if paths == [], do: %{}, else: Sobelow.MetaLog.get_templates(paths)

    Enum.each(vars, fn {finding, {template, ref_vars, vars}} ->
      template = template_name(template)

      {raw_funs, template_path} = get_rf_tp(templates, filename, controller, template)

      if raw_funs do
        uses = Enum.group_by(Parse.template_raw_uses(raw_funs.raw), &elem(&1, 0), &elem(&1, 1))
        assigns = Enum.map(ref_vars, &{&1, :high}) ++ Enum.map(vars, &{&1, :medium})
        report_assigns(assigns, uses, template_path, finding, base)
      end
    end)
  end

  defp report_assigns(assigns, uses, template, render, base) do
    Enum.each(assigns, fn {name, confidence} ->
      var = "@#{name}"

      if calls = Map.get(uses, var) do
        finding = %{
          base
          | vuln_source: render,
            vuln_variable: var,
            vuln_line_no: Parse.get_fun_line(render),
            vuln_col_no: Parse.get_fun_column(render),
            confidence: confidence,
            code_flows: template_flows(base.filename, render, template, calls, var)
        }

        add_finding(Finding.fetch_fingerprint(finding), template)
      end
    end)
  end

  defp template_flows(filename, render, template, calls, var) do
    if Sobelow.code_flows?() do
      source =
        Finding.flow_location(filename, render, "Render passes the #{var} assign to the template")

      calls
      |> Enum.map(&Finding.flow_location(template, &1, "raw outputs #{var}"))
      |> Enum.uniq()
      |> Enum.sort()
      |> Enum.map(&[source, &1])
    else
      []
    end
  end

  defp run_direct(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low
    inline = Parse.get_heex_raw_funs(fun, Map.get(meta_file, :file_path, meta_file.filename))

    {raw, assigns} =
      if is_list(fun) do
        {fun, Map.get(meta_file, :live_assigns, [])}
      else
        {inline,
         Map.get(Map.get(meta_file, :live_renders, %{}), Metadata.definition_key(fun), [])}
      end

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(
      fun,
      raw_findings(fun, inline),
      LiveView.raw_flows(raw, assigns, meta_file.filename)
    )
    |> Enum.each(&Print.add_finding(&1))
  end

  defp template_name(template) when is_atom(template), do: Atom.to_string(template) <> ".html"
  defp template_name(template) when is_binary(template), do: template
  defp template_name(_template), do: ""

  defp get_rf_tp(templates, controller_file, controller, template) do
    controller_file
    |> template_paths(controller, template)
    |> Enum.find_value({nil, nil}, fn path ->
      if templates[path], do: {templates[path], path}
    end)
  end

  defp template_paths(controller_file, controller, template) do
    controllers_dir = Path.dirname(controller_file)
    web_dir = Path.dirname(controllers_dir)

    for directory <- [
          Path.join([web_dir, "templates", controller]),
          Path.join(controllers_dir, controller <> "_html")
        ],
        extension <- ["eex", "heex"] do
      Path.join(directory, template <> "." <> extension)
    end
  end

  def parse_render_def(fun) do
    {params, {fun_name, line_no}} = Parse.get_fun_declaration(fun)

    pipefuns =
      Parse.get_pipe_funs(fun)
      |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
      |> Enum.flat_map(&Calls.get_piped_funs_of_type(&1, :render))

    pipevars =
      pipefuns
      |> Enum.map(&{&1, Parse.parse_render_opts(&1, params, 0)})
      |> List.flatten()

    vars =
      (Parse.get_funs_of_type(fun, :render) -- pipefuns)
      |> Enum.map(&{&1, Parse.parse_render_opts(&1, params, 1)})

    {vars ++ pipevars, params, {fun_name, line_no}}
  end

  def parse_raw_def(fun, file \\ "inline HEEx") do
    raw_findings(fun, Parse.get_heex_raw_funs(fun, file))
  end

  defp raw_findings(fun, inline) do
    {vars, params, declaration} = Parse.get_fun_vars_and_meta(fun, 0, :raw, :HTML)

    inline_vars =
      Enum.flat_map(inline, fn raw ->
        {raw_vars, _, _} = Parse.get_fun_vars_and_meta([raw], 0, :raw, :HTML)
        raw_vars
      end)

    {vars ++ inline_vars, params, declaration}
  end

  defp add_finding(finding, template) do
    t_name = Utils.normalize_path(template)

    case Sobelow.format() do
      "json" ->
        json_finding = [
          type: finding.type,
          file: finding.filename,
          variable: "#{finding.vuln_variable}",
          template: "#{t_name}",
          line: finding.vuln_line_no
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(finding, [
          Print.finding_file_name(finding.filename),
          Print.finding_line(finding.vuln_source),
          Print.finding_fun_metadata(finding.fun_name, finding.fun_line_no),
          "Template: #{t_name} - #{finding.vuln_variable}"
        ])

      "compact" ->
        Print.log_compact_finding(finding)

      "flycheck" ->
        Print.log_flycheck_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end
end
