defmodule Sobelow.HEEx do
  @moduledoc false

  @void_tags ~w(area base br col embed hr img input link meta param source track wbr)
  @tag ~r/\A<(\/?)([\w.:-]+)/
  @disable_attribute ~r/\Aphx-no-curly-interpolation(?:\s|=|\/?>)/

  def ast(source, file, line \\ 1) do
    if not String.valid?(source), do: syntax_error(file, line, 1)

    source =
      Regex.replace(~r/<%!--.*?--%>/s, source, fn comment ->
        String.replace(comment, ~r/[^\n]/u, " ")
      end)

    eex = EEx.compile_string(source, file: file, line: line)
    {:__block__, [], [eex | scan(source, file, line, 1, [], [])]}
  end

  defp scan("", _file, _line, _column, _stack, asts), do: Enum.reverse(asts)

  defp scan("<%" <> _ = source, file, line, column, stack, asts) do
    length = through(source, "%>")
    advance(source, length, file, line, column, stack, asts)
  end

  defp scan("<" <> _ = source, file, line, column, stack, asts) do
    case Regex.run(@tag, source) do
      [_prefix, closing, name] ->
        {size, tag_asts, disabled?} = tag(source, file, line, column, nil, 0, [], false)
        tag = binary_part(source, 0, size)
        tag_asts = if closing == "", do: tag_asts, else: []
        stack = update_stack(stack, tag, closing, String.downcase(name), disabled?)
        advance(source, byte_size(tag), file, line, column, stack, Enum.reverse(tag_asts) ++ asts)

      _ ->
        advance(source, 1, file, line, column, stack, asts)
    end
  end

  defp scan("{" <> rest = source, file, line, column, stack, asts) do
    if Enum.any?(stack, &elem(&1, 1)) do
      advance(source, 1, file, line, column, stack, asts)
    else
      case expression(rest, file, line, column + 1) do
        {length, ast} -> advance(source, length + 1, file, line, column, stack, [ast | asts])
        nil -> syntax_error(file, line, column)
      end
    end
  end

  defp scan(source, file, line, column, stack, asts) do
    <<char::utf8, _::binary>> = source
    advance(source, byte_size(<<char::utf8>>), file, line, column, stack, asts)
  end

  # Find the end of a tag and collect its expressions together. Attribute
  # expressions are parsed once, with the same source positions as body ones.
  defp tag("", _file, _line, _column, _quote, size, asts, disabled?),
    do: {size, Enum.reverse(asts), disabled?}

  defp tag(source, file, line, column, quote, size, asts, disabled?) do
    <<char::utf8, rest::binary>> = source
    width = byte_size(<<char::utf8>>)

    case {quote, char} do
      {nil, ?>} ->
        {size + width, Enum.reverse(asts), disabled?}

      {nil, char} when char in [?\s, ?\t, ?\n, ?\r, ?\f] ->
        # Only attribute names outside quoted values and Elixir expressions
        # can disable interpolation. Expression values are consumed below.
        disabled? = disabled? or Regex.match?(@disable_attribute, rest)
        {line, column} = location(<<char::utf8>>, line, column)
        tag(rest, file, line, column, nil, size + width, asts, disabled?)

      {nil, ?{} ->
        case expression(rest, file, line, column + 1) do
          {length, ast} ->
            consumed = binary_part(source, 0, length + 1)
            {line, column} = location(consumed, line, column)
            rest = binary_part(source, length + 1, byte_size(source) - length - 1)
            tag(rest, file, line, column, nil, size + length + 1, [ast | asts], disabled?)

          nil ->
            syntax_error(file, line, column + 1)
        end

      {nil, char} when char in [?", ?'] ->
        tag(rest, file, line, column + 1, char, size + width, asts, disabled?)

      {^char, _} ->
        tag(rest, file, line, column + 1, nil, size + width, asts, disabled?)

      _ ->
        {line, column} = location(<<char::utf8>>, line, column)
        tag(rest, file, line, column, quote, size + width, asts, disabled?)
    end
  end

  # Ask Elixir to recognize the complete expression. This also handles quoted
  # braces, sigils and nested maps without reproducing the Elixir tokenizer.
  defp expression(source, file, line, column), do: expression(source, file, line, column, 0)

  defp expression(source, file, line, column, offset) do
    case :binary.match(source, "}", scope: {offset, byte_size(source) - offset}) do
      {position, _} ->
        candidate = binary_part(source, 0, position)

        case Code.string_to_quoted(candidate,
               file: file,
               line: line,
               column: column,
               columns: true
             ) do
          {:ok, ast} ->
            # A brace inside a trailing comment is ignored by Elixir. Appending
            # it must be a syntax error for it to terminate this interpolation.
            case Code.string_to_quoted(candidate <> "}") do
              {:ok, _} -> expression(source, file, line, column, position + 1)
              {:error, _} -> {position + 1, ast}
            end

          {:error, _} ->
            expression(source, file, line, column, position + 1)
        end

      :nomatch ->
        nil
    end
  end

  defp syntax_error(file, line, column) do
    raise EEx.SyntaxError,
      message: "could not parse HEEx interpolation at column #{column}",
      file: file,
      line: line
  end

  defp update_stack(stack, _tag, "/", name, _disabled?) do
    case Enum.split_while(stack, &(elem(&1, 0) != name)) do
      {_, [_ | rest]} -> rest
      _ -> stack
    end
  end

  defp update_stack(stack, tag, "", name, disabled?) do
    if name in @void_tags or String.ends_with?(tag, "/>") do
      stack
    else
      [{name, disabled? or name in ["script", "style"]} | stack]
    end
  end

  defp through(source, ending) do
    case :binary.match(source, ending) do
      {position, length} -> position + length
      :nomatch -> byte_size(source)
    end
  end

  defp advance(source, length, file, line, column, stack, asts) do
    consumed = binary_part(source, 0, length)
    rest = binary_part(source, length, byte_size(source) - length)
    {line, column} = location(consumed, line, column)
    scan(rest, file, line, column, stack, asts)
  end

  defp location("\n", line, _column), do: {line + 1, 1}
  defp location(<<_char::utf8>>, line, column), do: {line, column + 1}

  defp location(source, line, column) do
    case String.split(source, "\n") do
      [single] -> {line, column + String.length(single)}
      lines -> {line + length(lines) - 1, String.length(List.last(lines)) + 1}
    end
  end
end
