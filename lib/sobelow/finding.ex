defmodule Sobelow.Finding do
  @moduledoc false

  defstruct [
    :type,
    :confidence,
    :filename,
    :vuln_line_no,
    :vuln_col_no,
    :vuln_variable,
    :vuln_source,
    :fun_name,
    :fun_line_no,
    :fun_source,
    :fingerprint,
    :legacy_fingerprint
  ]

  def init(type, filename, confidence \\ nil) do
    %Sobelow.Finding{
      type: type,
      filename: filename,
      confidence: confidence
    }
  end

  def multi_from_def(%Sobelow.Finding{} = finding, fun, {vulns, params, {fun_name, fun_line_no}}) do
    finding = %{finding | fun_name: fun_name, fun_line_no: fun_line_no, fun_source: fun}

    Enum.map(vulns, fn {vuln, var} ->
      %{
        finding
        | vuln_variable: var,
          vuln_source: vuln,
          vuln_line_no: Sobelow.Parse.get_fun_line(vuln),
          vuln_col_no: Sobelow.Parse.get_fun_column(vuln),
          confidence:
            if(Sobelow.Lexical.uncertain?(vuln),
              do: :low,
              else:
                Sobelow.Print.get_sev(
                  params,
                  if(finding.confidence in [nil, false],
                    do: confidence_variable(fun, vuln, var),
                    else: var
                  ),
                  finding.confidence
                )
            )
      }
      |> normalize()
    end)
  end

  # Follow only direct, top-level variable aliases before this sink. This can
  # recover confidence through `local = param` without guessing across branches
  # or function calls. The reported variable and fingerprint stay unchanged.
  defp confidence_variable(fun, vuln, vars) when is_list(vars) do
    Enum.map(vars, &confidence_variable(fun, vuln, &1))
  end

  defp confidence_variable({_, _, [_head, [do: _body]]} = fun, vuln, var) when is_atom(var) do
    case Sobelow.FunctionAnalysis.confidence_aliases(fun, vuln) do
      {:ok, aliases} -> Map.get(aliases, var, var)
      :error -> uncached_confidence_variable(fun, vuln, var)
    end
  end

  defp confidence_variable(_, _, var), do: var

  defp uncached_confidence_variable({_, _, [_head, [do: body]]}, vuln, var) do
    statements =
      case body do
        {:__block__, _, list} -> list
        single -> [single]
      end

    aliases =
      Enum.reduce_while(statements, %{}, fn statement, aliases ->
        if contains_node?(statement, vuln) do
          {:halt, aliases}
        else
          {:cont, track_alias(statement, aliases)}
        end
      end)

    Map.get(aliases, var, var)
  end

  defp contains_node?(ast, node) do
    {_, found?} =
      Macro.prewalk(ast, false, fn current, found? -> {current, found? or current == node} end)

    found?
  end

  defp track_alias({:=, _, [{left, _, nil}, {right, _, nil}]}, aliases)
       when is_atom(left) and is_atom(right) do
    Map.put(aliases, left, Map.get(aliases, right, right))
  end

  defp track_alias({:=, _, [{left, _, nil}, _]}, aliases) when is_atom(left) do
    Map.delete(aliases, left)
  end

  defp track_alias(_, aliases), do: aliases

  def fetch_fingerprint(%Sobelow.Finding{} = finding) do
    %{
      finding
      | fingerprint: fingerprint(finding),
        legacy_fingerprint: legacy_fingerprint(finding)
    }
  end

  def fingerprint(%Sobelow.Finding{} = finding) do
    filename = Sobelow.Scan.relative_filename(finding.filename)

    [finding.type, finding.vuln_source, filename, finding.vuln_line_no]
    |> :erlang.phash2()
    |> Integer.to_string(16)
  end

  def legacy_fingerprint(%Sobelow.Finding{} = finding) do
    filename = Sobelow.Scan.relative_filename(finding.filename)

    [finding.type, finding.vuln_source, filename, finding.vuln_line_no]
    |> :erlang.term_to_binary()
    |> :erlang.md5()
    |> Base.encode16()
  end

  defp normalize(%Sobelow.Finding{vuln_variable: vars} = finding) when is_list(vars) do
    var = if length(vars) > 1, do: Enum.join(vars, " and "), else: hd(vars)

    %{finding | vuln_variable: var} |> normalize()
  end

  defp normalize(%Sobelow.Finding{fun_source: fun} = finding) when is_list(fun) do
    %{finding | fun_source: List.first(fun)} |> normalize()
  end

  defp normalize(finding), do: finding

  defmacro __using__(_) do
    quote do
      alias Sobelow.Finding
      alias Sobelow.Parse
      alias Sobelow.Print
      alias Sobelow.Utils

      def details do
        @moduledoc
      end

      def id do
        "SBLW" <> String.pad_leading("#{@uid}", 3, "0")
      end

      def rule do
        [name, description] = String.split(@finding_type, ":", parts: 2)

        description = String.trim(description)

        rule_details =
          details()
          |> String.split("\n\n")
          |> Enum.map_join("\n\n", fn para -> String.replace(para, "\n", " ") end)

        %{
          id: id(),
          name: name,
          shortDescription: %{text: description},
          fullDescription: %{text: description},
          help: %{
            text: rule_details,
            markdown: rule_details
          }
        }
      end

      defoverridable details: 0
    end
  end
end

defmodule Sobelow.FindingType do
  @moduledoc false

  defmacro __using__(_) do
    quote do
      def finding_modules do
        @submodules
      end

      def details do
        Enum.map(@submodules, fn sub ->
          apply(sub, :details, [])
        end)
      end

      def rules do
        Enum.map(@submodules, fn sub ->
          apply(sub, :rule, [])
        end)
      end

      defoverridable details: 0
    end
  end
end
