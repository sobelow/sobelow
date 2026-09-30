defmodule Sobelow.Parse.Source do
  @moduledoc false

  def ast(filepath) do
    Sobelow.Scan.fetch({:ast, Path.expand(filepath), Sobelow.get_env(:skip)}, fn ->
      case read_file(filepath) do
        {:ok, content} -> parse(content, filepath)
        {:error, reason} -> unreadable_source(filepath, reason)
      end
    end)
  end

  @doc false
  # `ast/1`, plus a warning for any `# sobelow_skip` comment that could not be
  # read. An unrecognised comment is otherwise dropped in silence, which looks
  # exactly like a skip that did not apply — the two are indistinguishable to
  # someone whose comment simply has a stray space in it.
  #
  # Warn once during file preparation; router checks may request the same AST.
  def ast_with_skip_warnings(filepath) do
    case read_file(filepath) do
      {:ok, content} ->
        Sobelow.Scan.fetch({:skip_warnings, Path.expand(filepath)}, fn ->
          warn_unrecognised_skips(filepath, content)
        end)

        ast(filepath)

      {:error, reason} ->
        unreadable_source(filepath, reason)
    end
  end

  defp unreadable_source(filepath, reason) do
    Sobelow.Scan.record(
      filepath,
      :unreadable,
      "Could not read #{filepath}: #{:file.format_error(reason)}"
    )

    IO.puts(:stderr, "Could not read #{filepath}: #{:file.format_error(reason)}; skipping it.")
    {}
  end

  defp parse(content, filepath) do
    case Code.string_to_quoted(content, columns: true, file: filepath) do
      {:ok, ast} ->
        Sobelow.Scan.record(filepath, :scanned)
        ast

      {:error, {location, err, token}} ->
        syntax_error(filepath, location, err, token)
    end
  end

  defp syntax_error(filepath, location, err, token) do
    message = "#{filepath}:#{format_location(location)} #{format_error(err, token)}"
    Sobelow.Scan.record(filepath, :unparseable, message)

    if Application.get_env(:sobelow, :strict) do
      IO.puts(:stderr, message)
      System.halt(2)
    else
      {}
    end
  end

  @doc false
  # Some errors are reported as a `{prefix, suffix}` pair around the offending token.
  def format_error({prefix, suffix}, token), do: "#{prefix}#{token}#{suffix}"
  def format_error(err, token) when is_binary(err), do: "#{err}#{token}"
  def format_error(err, token), do: "#{inspect(err)}#{token}"

  @doc false
  # Elixir >= 1.13 reports the error location as a keyword list of metadata.
  # Older versions report a bare line number.
  def format_location(location) when is_list(location) do
    line = Keyword.get(location, :line)
    column = Keyword.get(location, :column)

    case {line, column} do
      {nil, _} -> ""
      {line, nil} -> "#{line}:"
      {line, column} -> "#{line}:#{column}:"
    end
  end

  def format_location(line) when is_integer(line), do: "#{line}:"
  def format_location(_), do: ""

  # A `# sobelow_skip` comment, rewritten into a module attribute so it survives
  # into the AST. Whitespace is deliberately loose: the spacing around the
  # marker and inside the list carries no meaning, and being strict about it
  # only produced comments that looked right and did nothing.
  @skip_comment ~r/#\s*sobelow_skip\s*(\[\s*"[^"]+"(?:\s*,\s*"[^"]+")*\s*,?\s*\])/

  # Anything that looks like an attempt at one. Requiring the bracket keeps
  # prose that merely mentions `# sobelow_skip` from being flagged.
  @skip_comment_attempt ~r/#\s*sobelow_skip\s*\[/

  defp read_file(filepath) do
    case Sobelow.Scan.source(filepath) do
      {:ok, content} ->
        if Sobelow.get_env(:skip) do
          {:ok, String.replace(content, @skip_comment, "@sobelow_skip \\g{1}")}
        else
          {:ok, content}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Runs against the rewritten content, so every comment that was understood has
  # already become an attribute and whatever still reads as a skip comment is
  # one we could not parse.
  defp warn_unrecognised_skips(filepath, content) do
    if Sobelow.get_env(:skip) do
      content
      |> String.split("\n")
      |> Enum.with_index(1)
      |> Enum.each(fn {line, line_no} ->
        if Regex.match?(@skip_comment_attempt, line),
          do: warn_unrecognised_skip(filepath, line_no)
      end)
    end
  end

  defp warn_unrecognised_skip(filepath, line_no) do
    IO.puts(
      :stderr,
      "#{filepath}:#{line_no}: could not read this `# sobelow_skip` comment, so it was " <>
        "ignored. Expected a list of double-quoted checks, " <>
        ~s(for example: # sobelow_skip ["Config.CSRF"])
    )
  end
end
