defmodule Sobelow.Parse.XMLOptions do
  @moduledoc false

  # Deliberately require explicit options, not version-dependent defaults.
  # Last duplicate wins, just as xmerl's left-to-right option parsing does.
  def risky?(:scan, options) when is_list(options) do
    option(options, :allow_entities) == true
  end

  def risky?(:sax, options) when is_list(options) do
    external = option(options, :external_entities) in [:all, :file]
    recursion = option(options, :entity_recurse_limit)
    expansion = is_integer(recursion) and recursion > 3 and :disallow_entities not in options
    external or expansion
  end

  def risky?(_, _), do: false

  defp option(options, name) do
    Enum.reduce(options, nil, fn
      {^name, value}, _ -> value
      _, previous -> previous
    end)
  end
end
