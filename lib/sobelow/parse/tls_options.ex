defmodule Sobelow.Parse.TLSOptions do
  @moduledoc false

  @tls_option_keys [:ssl, :ssl_options, :transport_opts, :connect_options, :tls, :tls_opts]

  def calls(ast, matcher, skipped_functions) do
    {_, calls} =
      Macro.prewalk(ast, [], fn node, acc ->
        if MapSet.member?(skipped_functions, node),
          do: {{}, acc},
          else: collect(node, acc, matcher)
      end)

    Enum.reverse(calls)
  end

  defp collect({name, _, args} = call, acc, matcher)
       when is_list(args) and name != :%{} do
    hackney? = hackney_call?(name) or Sobelow.Lexical.erlang_imported?(call, :hackney)

    context = %{
      hackney?: hackney?,
      tls?:
        direct_tls_options?(name) or Sobelow.Lexical.erlang_imported?(call, :ssl) or
          (name == :wt_connect and hackney?)
    }

    if options?(args, context, matcher),
      do: {call, [call | acc]},
      else: {call, acc}
  end

  defp collect(node, acc, _matcher), do: {node, acc}

  defp options?(options, context, matcher) do
    Enum.any?(options, fn option ->
      matcher.(option, context) or nested_options?(option, context, matcher)
    end)
  end

  defp nested_options?(options, context, matcher) when is_list(options),
    do: options?(options, context, matcher)

  defp nested_options?({:%{}, _, entries}, context, matcher) when is_list(entries),
    do: options?(entries, context, matcher)

  defp nested_options?({kind, _, [left, right]}, context, matcher) when kind in [:|, :++],
    do: options?([left, right], context, matcher)

  defp nested_options?({key, options}, context, matcher) when is_list(options) do
    options?(options, option_context(context, key), matcher)
  end

  defp nested_options?({key, {:++, _, _} = options}, context, matcher),
    do: nested_options?(options, option_context(context, key), matcher)

  defp nested_options?(_, _, _), do: false

  defp option_context(context, key) do
    %{
      hackney?: context.hackney? or key == :hackney,
      tls?: context.tls? or key in @tls_option_keys
    }
  end

  defp hackney_call?({:., _, [:hackney, _]}), do: true
  defp hackney_call?(_), do: false

  defp direct_tls_options?({:., _, [:ssl, _]}), do: true
  defp direct_tls_options?({:., _, [:hackney, :wt_connect]}), do: true
  defp direct_tls_options?(_), do: false
end
