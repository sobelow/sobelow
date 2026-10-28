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

    piped =
      fun |> Parse.get_pipe_funs() |> Map.new(fn {:|>, _, [value, call]} -> {call, value} end)

    consult = calls(fun, :consult, 1, 0, piped)
    filenames = calls(fun, :path_consult, 2, 1, piped)

    directories =
      calls(fun, :path_consult, 2, 0, piped)
      |> Enum.reject(fn {{_, _, args}, _} -> absolute_literal?(List.last(args)) end)

    findings =
      (consult ++ filenames ++ directories)
      |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
      |> Enum.map(fn {call, variables} -> {call, variables |> List.flatten() |> Enum.uniq()} end)

    {findings, params, declaration}
  end

  defp calls(fun, name, arity, index, piped) do
    {calls, _, _} = Parse.get_erlang_fun_vars_and_meta(fun, index, name, :file)
    variables_by_call = Map.new(calls)

    # Select calls before variable extraction can discard legacy charlist interpolation.
    fun
    |> Parse.get_erlang_aliased_funs_of_type(name, :file)
    |> Enum.flat_map(fn {_, _, args} = call ->
      args = if Map.has_key?(piped, call), do: [Map.fetch!(piped, call) | args], else: args

      if length(args) == arity do
        argument = Enum.at(args, index)
        normalized = normalize_charlists(argument)

        variables =
          if normalized == argument,
            do: Map.get(variables_by_call, call, []),
            else: Parse.extract_opts({:argument, [], [normalized]}, 0)

        case List.flatten(List.wrap(variables)) do
          [] -> []
          variables -> [{call, variables}]
        end
      else
        []
      end
    end)
  end

  # Inspect charlist contents like string contents without changing the reported AST.
  defp normalize_charlists(ast) do
    Macro.prewalk(ast, fn
      {sigil, _, [{:<<>>, _, _} = contents, []]} when sigil in [:sigil_c, :sigil_C] ->
        contents

      {{:., _, [List, :to_charlist]}, meta, [contents]} when is_list(contents) ->
        {:<<>>, meta, contents}

      node ->
        node
    end)
  end

  # An absolute filename makes path_consult ignore its search directories.
  defp absolute_literal?(value) when is_binary(value), do: Path.type(value) == :absolute

  defp absolute_literal?(value) when is_list(value) do
    List.ascii_printable?(value) and absolute_literal?(List.to_string(value))
  end

  defp absolute_literal?({sigil, _, [{:<<>>, _, [value]}, []]})
       when sigil in [:sigil_c, :sigil_C] and is_binary(value),
       do: absolute_literal?(value)

  defp absolute_literal?(_), do: false
end
