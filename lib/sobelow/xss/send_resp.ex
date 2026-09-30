defmodule Sobelow.XSS.SendResp do
  @moduledoc """
  # XSS in `send_resp`

  This submodule looks for XSS vulnerabilities in the `body`
  argument of `Conn.send_resp`.

  A known data content type on the response connection suppresses the finding.
  Both `put_resp_content_type` and `put_resp_header` with the literal
  `"content-type"` header are recognized. HTML and SVG retain their confidence;
  dynamic, malformed, and other scriptable document types remain low-confidence
  findings.

  SendResp checks can be ignored with the following command:

      $ mix sobelow -i XSS.SendResp
  """
  @uid 31
  @finding_type "XSS.SendResp: XSS in `send_resp`"
  @setters [:put_resp_content_type, :put_resp_header]
  @media_type ~r/\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\/[!#$%&'*+.^_`|~0-9A-Za-z-]+\z/
  @http_whitespace ~r/\A[ \t\r\n]+|[ \t\r\n]+\z/
  @unknown_media_types ["unknown/unknown", "application/unknown", "*/*"]

  use Sobelow.Finding

  def run(fun, meta_file) do
    Finding.init(@finding_type, meta_file.filename, nil)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Stream.map(&set_confidence/1)
    |> Stream.reject(&nil_confidence?/1)
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 2, :send_resp, :Conn)
  end

  @doc false
  def get_content_type({:put_resp_content_type, _, opts}), do: content_type_arg(opts)
  def get_content_type({{_, _, [_, :put_resp_content_type]}, _, opts}), do: content_type_arg(opts)

  def get_content_type({:put_resp_header, _, opts}), do: header_content_type_arg(opts)

  def get_content_type({{_, _, [_, :put_resp_header]}, _, opts}),
    do: header_content_type_arg(opts)

  def get_content_type(_), do: :unknown

  defp header_content_type_arg([_conn, "content-type", type]), do: type
  defp header_content_type_arg(_), do: :unknown

  defp content_type_arg([type, options]) when is_list(options), do: type
  defp content_type_arg([_conn, type | _]), do: type
  defp content_type_arg([type]), do: type
  defp content_type_arg(_), do: nil

  @doc false
  def set_confidence(%Finding{} = finding) do
    confidence =
      case response_content_type(finding) do
        :unknown -> finding.confidence
        type when is_binary(type) -> literal_confidence(type, finding.confidence)
        _ -> :low
      end

    %{finding | confidence: confidence}
  end

  defp response_content_type(%Finding{fun_source: {_, _, [_head, [do: body]]}} = finding) do
    statements =
      case body do
        {:__block__, _, list} -> list
        single -> [single]
      end

    Enum.reduce_while(statements, %{}, fn statement, types ->
      if contains_call?(statement, finding.vuln_source) do
        conn = response_connection(statement, finding.vuln_source)

        types = types_before(statement, finding.vuln_source, types)
        {:halt, connection_content_type(conn, types)}
      else
        {:cont, track_assignment(statement, types)}
      end
    end)
    |> case do
      types when is_map(types) -> :unknown
      type -> type
    end
  end

  defp response_content_type(_), do: :unknown

  defp contains_call?(ast, call) do
    {_, found?} = Macro.prewalk(ast, false, fn node, found? -> {node, found? or node == call} end)
    found?
  end

  defp types_before(call, call, types), do: types

  defp types_before({:cond, _, [[do: clauses]]}, call, types) do
    case Enum.find(clauses, &contains_call?(&1, call)) do
      {:->, _, [[condition], body]} ->
        types_before([condition, body], call, types)

      _ ->
        types
    end
  end

  defp types_before({:->, _, [patterns, body]}, call, types) do
    # Callback arguments and case/rescue patterns shadow outer bindings. Pins
    # and guard expressions do not bind variables.
    types_before(body, call, Map.drop(types, bound_variables(patterns)))
  end

  defp types_before({_name, _, args}, call, types) when is_list(args),
    do: types_before(args, call, types)

  defp types_before({_key, value}, call, types), do: types_before(value, call, types)

  defp types_before(nodes, call, types) when is_list(nodes) do
    Enum.reduce_while(nodes, types, fn node, types ->
      if contains_call?(node, call),
        do: {:halt, types_before(node, call, types)},
        else: {:cont, track_assignment(node, types)}
    end)
  end

  defp types_before(_node, _call, types), do: types

  defp response_connection(statement, call) do
    pipe =
      statement
      |> Parse.get_funs_of_type(:|>)
      |> Enum.find(fn {:|>, _, [_, right]} -> right == call end)

    case pipe do
      {:|>, _, [left, _]} -> left
      nil -> call |> elem(2) |> List.first()
    end
  end

  defp track_assignment({:=, _, [{name, _, nil}, value]}, types) when is_atom(name) do
    types = track_assignment(value, types)
    Map.put(types, name, connection_content_type(value, types))
  end

  defp track_assignment({kind, _, [pattern, value]}, types) when kind in [:=, :<-],
    do: value |> track_assignment(types) |> Map.drop(bound_variables(pattern))

  defp track_assignment({kind, _, [condition | _]}, types) when kind in [:if, :unless, :case],
    do: track_assignment(condition, types)

  defp track_assignment({kind, _, _}, types)
       when kind in [:fn, :cond, :with, :for, :try, :->, :quote, :def, :defp],
       do: types

  defp track_assignment({_name, _, args}, types) when is_list(args),
    do: Enum.reduce(args, types, &track_assignment/2)

  defp track_assignment(nodes, types) when is_list(nodes),
    do: Enum.reduce(nodes, types, &track_assignment/2)

  defp track_assignment({_key, value}, types), do: track_assignment(value, types)
  defp track_assignment(_, types), do: types

  defp bound_variables(patterns) do
    {_, names} =
      Macro.prewalk(patterns, [], fn
        {:^, _, _}, names -> {[], names}
        {:when, _, args}, names -> {Enum.drop(args, -1), names}
        {name, _, nil} = node, names when is_atom(name) -> {node, [name | names]}
        node, names -> {node, names}
      end)

    names
  end

  defp connection_content_type({:|>, _, [conn, setter]}, types) do
    if setter?(setter, 1) do
      # Supply the piped connection only for argument selection. Findings keep
      # the original call AST and therefore their existing locations and hashes.
      {name, meta, args} = setter
      setter_content_type({name, meta, [conn | args]}, types)
    else
      # Another operation after setting the header may alter the connection.
      # Keep the finding when that operation is not understood.
      :unknown
    end
  end

  defp connection_content_type({name, _, nil}, types) when is_atom(name) do
    Map.get(types, name, :unknown)
  end

  defp connection_content_type(setter, types) do
    if setter?(setter), do: setter_content_type(setter, types), else: :unknown
  end

  defp setter_content_type({name, _, [conn, header, _value]} = setter, types)
       when is_binary(header) do
    header_setter? = name == :put_resp_header or match?({:., _, [_, :put_resp_header]}, name)

    if header_setter? and String.downcase(header) != "content-type",
      do: connection_content_type(conn, types),
      else: get_content_type(setter)
  end

  defp setter_content_type(setter, _types), do: get_content_type(setter)

  defp setter?(setter, extra \\ 0)

  defp setter?({name, _, args} = setter, extra) when name in @setters and is_list(args),
    do: Sobelow.Lexical.unqualified?(setter, :Conn, extra)

  defp setter?({{:., _, [{:__aliases__, _, aliases}, name]}, _, args} = setter, _extra)
       when name in @setters and is_list(args) do
    case Sobelow.Lexical.matches?(setter, :Conn) do
      nil -> List.last(aliases) == :Conn
      matched? -> matched?
    end
  end

  defp setter?(_, _extra), do: false

  defp literal_confidence(content_type, confidence) do
    original =
      content_type
      |> String.split(";", parts: 2)
      |> hd()
      |> String.replace(@http_whitespace, "")

    media_type = String.downcase(original)

    cond do
      not Regex.match?(@media_type, original) ->
        :low

      media_type in @unknown_media_types ->
        :low

      String.contains?(media_type, "html") or media_type == "image/svg+xml" ->
        confidence

      String.ends_with?(media_type, "+xml") or
          media_type in ["text/xml", "application/xml", "application/pdf"] ->
        :low

      true ->
        nil
    end
  end

  @doc false
  def nil_confidence?(%Finding{confidence: nil}), do: true
  def nil_confidence?(_), do: false
end
