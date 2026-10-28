defmodule Sobelow.XSS.ContentDisposition do
  @moduledoc false

  @attachment ~r/\A[ \t]*attachment[ \t]*(.*)\z/i
  @parameter ~r"""
  \A;[ \t]*([!#$%&'*+.^_\x60|~0-9A-Za-z-]+)[ \t]*=[ \t]*
  ([!#$%&'*+.^_\x60|~0-9A-Za-z-]+|"(?:[\t\x20-\x21\x23-\x5B\x5D-\x7E]|\\[\t\x20-\x7E])*")
  [ \t]*(.*)\z
  """x
  # Recognize common extended filename values with a known charset and no
  # language tag. Unsupported extended forms remain uncertain.
  @extended ~r"""
  \A(UTF-8|ISO-8859-1)''((?:[!#$&+.^_\x60|~0-9A-Za-z-]|%[0-9A-Fa-f]{2})*)\z
  """ix

  def attachment?(value) when is_binary(value) do
    case Regex.run(@attachment, value, capture: :all_but_first) do
      [parameters] -> parameters?(parameters, MapSet.new())
      _ -> false
    end
  end

  def attachment?(_value), do: false

  defp parameters?("", _seen), do: true

  defp parameters?(parameters, seen) do
    case Regex.run(@parameter, parameters, capture: :all_but_first) do
      [name, value, rest] ->
        name = String.downcase(name)

        not MapSet.member?(seen, name) and
          valid_value?(name, value) and parameters?(rest, MapSet.put(seen, name))

      _ ->
        false
    end
  end

  defp valid_value?(name, value) do
    not String.ends_with?(name, "*") or valid_extended?(value)
  end

  defp valid_extended?(value) do
    case Regex.run(@extended, value, capture: :all_but_first) do
      [charset, encoded] ->
        String.downcase(charset) != "utf-8" or String.valid?(URI.decode(encoded))

      _ ->
        false
    end
  end
end
