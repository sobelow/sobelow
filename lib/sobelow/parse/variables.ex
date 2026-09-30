defmodule Sobelow.Parse.Variables do
  @moduledoc false

  @operators [
    :+,
    :-,
    :!,
    :^,
    :not,
    :"~~~",
    :*,
    :/,
    :++,
    :--,
    :..,
    :<>,
    :<<<,
    :>>>,
    :~>>,
    :<<~,
    :>,
    :<,
    :>=,
    :<=,
    :==,
    :!=,
    :=~,
    :===,
    :!==,
    :&&,
    :&&&,
    :and,
    :||,
    :|||,
    :or,
    :=,
    :|
  ]

  def normalize_finding({finding, opts}) when is_list(opts) do
    {finding, List.flatten(opts)}
  end

  # This handles normalizations for the case where the finding is a dot-access tuple
  def normalize_finding({finding, {:., _, [{var, _, _}, field]}}) when is_atom(field) do
    {finding, "#{atom_to_string(var)}.#{atom_to_string(field)}"}
  end

  def normalize_finding({finding, opt}) do
    {finding, [opt]}
  end

  defp atom_to_string(atom) when is_atom(atom), do: Atom.to_string(atom)

  def extract_opts({:send_resp, _, nil}), do: []
  def extract_opts({:send_resp, _, opts}), do: parse_opts(List.last(opts))

  def extract_opts({{:., _, _}, _, _opts} = fun) do
    parse_opts(fun)
  end

  def extract_opts({:<<>>, _, opts}) do
    opts
    |> Enum.map(&parse_string_interpolation/1)
  end

  def extract_opts({val, _, nil}), do: [val]
  def extract_opts({val, _, []}), do: [val]

  def extract_opts({_, _, opts}) when is_list(opts) do
    opts
    |> Enum.map(&parse_opts/1)
  end

  def extract_opts(opts) when is_list(opts), do: Enum.map(opts, &parse_opts/1)
  def extract_opts(_), do: []

  # Extract the tainted argument at the check's zero-based argument index.
  def extract_opts({_, _, nil}, _idx), do: []

  def extract_opts({_, _, opts}, idx) do
    parse_opts(Enum.at(opts, idx))
  end

  defp parse_opts({:@, _, _}), do: []
  defp parse_opts({key, _, nil}), do: key

  defp parse_opts({:<<>>, _, opts}) do
    Enum.map(opts, &parse_string_interpolation/1)
    |> List.flatten()
  end

  defp parse_opts({{:., _, [Access, :get]}, _, [{{:., _, [{:conn, _, nil}, :params]}, _, _}, _]}) do
    "conn.params"
  end

  defp parse_opts({{:., _, [Access, :get]}, _, [{val, _, _} | _]}), do: val
  defp parse_opts({{:., _, [Access, :get]}, _, [value | _]}), do: parse_opts(value)

  defp parse_opts({{:., _, _}, _, [{:var!, _, [{:assigns, _, EEx.Engine}]}, var]}) do
    "@#{var}"
  end

  defp parse_opts({{:., _, [{:__aliases__, _, module}, _func]}, _, _}) do
    Module.concat(module)
  end

  # This is what an accessor func looks like, eg conn.params
  defp parse_opts({{:., _, [{val, _, nil}, _]}, _, _}), do: val
  defp parse_opts({:., _, [{val, _, nil}, _]}), do: val

  defp parse_opts({{:., _, opts}, _, _} = _fun) do
    parse_opts(opts)
  end

  defp parse_opts({:&, _, [i]} = cap) when is_integer(i), do: Macro.to_string(cap)

  defp parse_opts({fun, _, opts}) when fun in @operators do
    Enum.map(opts, &parse_opts/1)
  end

  # Sigils aren't ordinary function calls.
  defp parse_opts({fun, _, _}) when fun in [:sigil_s, :sigil_e], do: []
  defp parse_opts({fun, _, opts}) when is_list(opts), do: fun
  defp parse_opts(opts) when is_tuple(opts), do: parse_opts(Tuple.to_list(opts))
  defp parse_opts(opts) when is_list(opts), do: Enum.map(opts, &parse_opts/1)
  defp parse_opts(_), do: []

  def get_fun_declaration(ast) do
    Sobelow.FunctionAnalysis.fetch(ast, :declaration, fn -> do_get_fun_declaration(ast) end)
  end

  defp do_get_fun_declaration({_, _, fun_opts}) do
    [definition | _] = fun_opts

    declaration =
      case definition do
        {:when, _, [opts | _]} -> opts
        opts -> opts
      end

    params = get_params(declaration)
    {fun_name, _, _} = declaration

    {params, {fun_name, get_fun_line(declaration)}}
  end

  defp do_get_fun_declaration(_) do
    {[], {"", ""}}
  end

  ## Get function parameters.
  defp get_params({_, _, params}) when is_list(params) do
    Enum.flat_map(params, &get_params/1)
  end

  defp get_params({_, params}) when is_tuple(params) do
    get_params(params)
  end

  defp get_params({var, _, nil}), do: [var]
  defp get_params(_), do: []

  def get_pipe_val(ast, pipe_fun) do
    Sobelow.FunctionAnalysis.fetch(ast, {:pipe_value, pipe_fun}, fn ->
      {_, acc} = Macro.prewalk(ast, [], &get_pipe_val(&1, &2, pipe_fun))
      acc
    end)
  end

  def get_pipe_val({:|>, _, [{:|>, _, opts}, pipefun]}, acc, pipefun) do
    key = extract_opts(List.last(opts))
    {[], [key | acc]}
  end

  def get_pipe_val({:|>, _, [opts, pipefun]}, acc, pipefun) do
    key = extract_opts(opts)
    {[], [key | acc]}
  end

  def get_pipe_val({:|>, _, [{fun, _, funopts} = opts, maybe_pipe]} = ast, acc, pipe)
      when fun not in [:|>] do
    {_, match_pipe} = Macro.prewalk(maybe_pipe, [], &get_match(&1, &2, pipe))
    {_, match_opts} = Macro.prewalk(opts, [], &get_match(&1, &2, pipe))

    cond do
      !Enum.empty?(match_pipe) ->
        {maybe_pipe, acc}

      !Enum.empty?(match_opts) ->
        key = extract_opts(funopts)
        {[], [key | acc]}

      true ->
        {ast, acc}
    end
  end

  def get_pipe_val(ast, acc, _pipe), do: {ast, acc}

  defp get_match(match, acc, match), do: {[], [match | acc]}
  defp get_match(ast, acc, _), do: {ast, acc}

  defp parse_string_interpolation({key, _, nil}), do: key

  defp parse_string_interpolation({:"::", _, opts}) do
    parse_string_interpolation(opts)
  end

  defp parse_string_interpolation([{{:., _, [Kernel, :to_string]}, _, vars}, _]) do
    Enum.map(vars, &parse_opts/1)
  end

  defp parse_string_interpolation({{:., _, [Kernel, :to_string]}, _, opts}) do
    Enum.map(opts, &parse_opts/1)
  end

  defp parse_string_interpolation({:<<>>, _, opts}) do
    opts
    |> Enum.map(&parse_string_interpolation/1)
  end

  defp parse_string_interpolation(_) do
    []
  end

  def get_fun_line({_, meta, _}) when is_list(meta) do
    Keyword.get(meta, :line, 0)
  end

  def get_fun_column({_, meta, _}) when is_list(meta) do
    Keyword.get(meta, :column, 0)
  end
end
