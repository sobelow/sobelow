defmodule Sobelow.XSS.Raw do
  @moduledoc """
  # XSS in `raw`

  This submodule checks for the use of `raw` in templates
  as this can lead to XSS vulnerabilities if taking user input.

  Raw checks can be ignored with the following command:

      $ mix sobelow -i XSS.Raw
  """
  @uid 30
  @finding_type "XSS.Raw: XSS"

  use Sobelow.Finding

  def run(fun, meta_file, _, nil) do
    run_direct(fun, meta_file)
  end

  def run(fun, meta_file, _web_root, controller) do
    run_direct(fun, meta_file)

    {vars, _, {fun_name, line_no}} = parse_render_def(fun)
    filename = meta_file.filename

    paths =
      Enum.flat_map(vars, fn {_finding, {template, _refs, _vars}} ->
        template_paths(filename, controller, template_name(template))
      end)

    # Take one snapshot per function, containing only its possible templates.
    # Earlier renders can delete raw entries; later renders in this function
    # must still see the snapshot used by the historical correlation logic.
    templates = if paths == [], do: %{}, else: Sobelow.MetaLog.get_templates(paths)

    Enum.each(vars, fn {finding, {template, ref_vars, vars}} ->
      template = template_name(template)

      {raw_funs, template_path} = get_rf_tp(templates, filename, controller, template)

      if raw_funs do
        raw_vals = Parse.get_template_vars(raw_funs.raw)

        Enum.each(ref_vars, fn var ->
          var = "@#{var}"

          if Enum.member?(raw_vals, var) do
            Sobelow.MetaLog.delete_raw(var, template_path)
            t_name = String.replace_prefix(Path.expand(template_path, ""), "/", "")
            add_finding(t_name, line_no, filename, fun_name, fun, var, :high, finding)
          end
        end)

        Enum.each(vars, fn var ->
          var = "@#{var}"

          if Enum.member?(raw_vals, var) do
            Sobelow.MetaLog.delete_raw(var, template_path)
            t_name = String.replace_prefix(Path.expand(template_path, ""), "/", "")
            add_finding(t_name, line_no, filename, fun_name, fun, var, :medium, finding)
          end
        end)
      end
    end)
  end

  defp run_direct(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(
      fun,
      parse_raw_def(fun, Map.get(meta_file, :file_path, meta_file.filename))
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
      |> Enum.flat_map(&Parse.get_funs_of_type(&1, :render))

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
    {vars, params, declaration} = Parse.get_fun_vars_and_meta(fun, 0, :raw, :HTML)

    inline_vars =
      fun
      |> Parse.get_heex_raw_funs(file)
      |> Enum.flat_map(fn raw ->
        {raw_vars, _, _} = Parse.get_fun_vars_and_meta([raw], 0, :raw, :HTML)
        raw_vars
      end)

    {vars ++ inline_vars, params, declaration}
  end

  defp add_finding(t_name, line_no, filename, fun_name, fun, var, severity, finding) do
    finding =
      %Finding{
        type: @finding_type,
        filename: filename,
        fun_source: fun,
        vuln_source: finding,
        vuln_variable: var,
        vuln_line_no: Parse.get_fun_line(finding),
        vuln_col_no: Parse.get_fun_column(finding),
        confidence: severity
      }
      |> Finding.fetch_fingerprint()

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
          Print.finding_file_name(filename),
          Print.finding_line(finding.vuln_source),
          Print.finding_fun_metadata(fun_name, line_no),
          "Template: #{t_name} - #{var}"
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
