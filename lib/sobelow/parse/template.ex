defmodule Sobelow.Parse.Template do
  @moduledoc false

  alias Sobelow.Parse.Calls

  def get_meta_template_funs(filepath) do
    case Sobelow.Scan.fetch({:template, Path.expand(filepath)}, fn -> template_ast(filepath) end) do
      {:ok, ast} -> get_meta_template_fun(ast)
      :error -> %{raw: [], ast: {}}
    end
  end

  # A template we cannot parse should be skipped like an unparseable `.ex` file,
  # not abort the whole scan.
  defp template_ast(filepath) do
    case Sobelow.Scan.source(filepath) do
      {:ok, source} ->
        ast =
          if Path.extname(filepath) == ".heex" do
            source |> Sobelow.HEEx.ast(filepath) |> heex_assigns()
          else
            EEx.compile_string(source, file: filepath)
          end

        Sobelow.Scan.record(filepath, :scanned)
        {:ok, ast}

      {:error, reason} ->
        message = "Could not read #{filepath}: #{:file.format_error(reason)}"
        Sobelow.Scan.record(filepath, :unreadable, message)
        IO.puts(:stderr, message <> "; skipping it.")
        :error
    end
  rescue
    e in EEx.SyntaxError ->
      Sobelow.Scan.record(filepath, :unparseable, Exception.message(e))

      if Application.get_env(:sobelow, :strict) do
        IO.puts(:stderr, Exception.message(e))
        System.halt(2)
      else
        :error
      end
  end

  @doc false
  def get_heex_raw_funs(ast, file \\ "inline HEEx") do
    {_, raw} =
      Macro.prewalk(ast, [], fn
        {:sigil_H, meta, [{:<<>>, literal_meta, [source]}, _]} = node, acc
        when is_binary(source) ->
          line_offset =
            if Keyword.get(meta, :delimiter) in ["\"\"\"", "'''"] do
              Keyword.get(meta, :line, 0)
            else
              Keyword.get(meta, :line, 1) - 1
            end

          found =
            source
            |> inline_heex_ast(file, line_offset + 1)
            |> shift_inline_columns(meta, literal_meta, line_offset + 1)
            |> heex_assigns()
            |> Sobelow.Lexical.index_inline(node)
            |> get_meta_template_fun()
            |> Map.fetch!(:raw)

          {node, found ++ acc}

        node, acc ->
          {node, acc}
      end)

    raw
  end

  defp inline_heex_ast(source, file, line) do
    Sobelow.HEEx.ast(source, file, line)
  rescue
    e in EEx.SyntaxError ->
      Sobelow.Scan.record(file, :unparseable, Exception.message(e))

      if Sobelow.get_env(:strict) do
        IO.puts(:stderr, Exception.message(e))
        System.halt(2)
      end

      {}
  end

  defp shift_inline_columns(ast, sigil, literal, first_line) do
    heredoc? = Keyword.get(sigil, :delimiter) in ["\"\"\"", "'''"]
    indentation = Keyword.get(literal, :indentation, 0)

    prefix =
      if is_integer(sigil[:column]),
        do: sigil[:column] + 1 + String.length(Keyword.get(sigil, :delimiter, "\"")),
        else: 0

    Macro.prewalk(ast, fn
      {name, meta, args} = node when is_list(meta) ->
        offset =
          if heredoc?,
            do: indentation,
            else: if(Keyword.get(meta, :line) == first_line, do: prefix, else: 0)

        if is_integer(meta[:column]),
          do: {name, Keyword.update!(meta, :column, &(&1 + offset)), args},
          else: node

      node ->
        node
    end)
  end

  # The EEx engine represents `@name` as an access on `assigns`. Reuse that
  # representation so existing taint extraction and template correlation see
  # the same variable for both EEx and HEEx expressions.
  defp heex_assigns(ast) do
    Macro.prewalk(ast, fn
      {:@, meta, [{name, _, nil}]} when is_atom(name) ->
        {{:., meta, [{:__aliases__, meta, [:EEx, :Engine]}, :fetch_assign!]}, meta,
         [{:var!, meta, [{:assigns, meta, EEx.Engine}]}, name]}

      node ->
        node
    end)
  end

  def get_meta_template_fun(ast) do
    init_acc = %{raw: [], ast: ast}
    {_, acc} = Macro.prewalk(ast, init_acc, &get_meta_template_fun(&1, &2))
    acc
  end

  # Keep the entire pipe so taint extraction includes its left-hand value.
  def get_meta_template_fun({:|>, _, [_, {:raw, _, _}]} = ast, acc) do
    {ast, Map.update!(acc, :raw, &[ast | &1])}
  end

  def get_meta_template_fun(
        {:|>, _, [_, {{:., _, [{:__aliases__, _, modules}, :raw]}, _, _} = call]} = ast,
        acc
      ) do
    if Calls.alias_matches?(call, modules, :HTML),
      do: {ast, Map.update!(acc, :raw, &[ast | &1])},
      else: {ast, acc}
  end

  def get_meta_template_fun({:raw, _, _} = ast, acc) do
    {ast, Map.update!(acc, :raw, &[ast | &1])}
  end

  def get_meta_template_fun({{:., _, [{:__aliases__, _, modules}, :raw]}, _, _} = ast, acc) do
    if Calls.alias_matches?(ast, modules, :HTML),
      do: {ast, Map.update!(acc, :raw, &[ast | &1])},
      else: {ast, acc}
  end

  def get_meta_template_fun(ast, acc), do: {ast, acc}

  def get_template_vars(raw_funs) do
    Enum.flat_map(raw_funs, fn ast ->
      {vars, _, _} = Calls.get_fun_vars_and_meta([ast], 0, :raw, :HTML)

      Enum.flat_map(vars, fn {_, var} ->
        var
      end)
    end)
  end

  def parse_render_opts({:render, _, opts}, params, idx) do
    {_, vars} = Macro.prewalk(opts, [], &extract_render_opts/2)

    template = if is_nil(opts) || Enum.empty?(opts), do: "", else: Enum.at(opts, idx)

    reflected_vars =
      Enum.filter(vars, fn var ->
        (reflected_var?(var) && in_params?(var, params)) || conn_params?(var)
      end)

    var_keys =
      Enum.map(vars, fn {key, val} ->
        case val do
          {_, _, _} -> key
          _ -> nil
        end
      end)

    reflected_var_keys = Keyword.keys(reflected_vars)

    {template, reflected_var_keys, var_keys -- reflected_var_keys}
  end

  def extract_render_opts(ast, acc) do
    if Keyword.keyword?(ast) do
      {ast, ast}
    else
      {ast, acc}
    end
  end

  defp reflected_var?({_, {_, _, nil}}), do: true
  defp reflected_var?(_), do: false

  defp in_params?({_, {var, _, _}}, params) do
    Enum.member?(params, var)
  end

  def conn_params?({_, {{:., _, [Access, :get]}, _, access_opts}}),
    do: conn_params?(access_opts)

  def conn_params?([{{:., _, [{:conn, _, nil}, :params]}, _, []}, _]), do: true
  def conn_params?(_), do: false
end
