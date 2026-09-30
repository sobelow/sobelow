defmodule Sobelow.Config do
  @moduledoc """
  # Configuration

  Submodules contained within this vulnerability type
  are related to common insecurities found in how
  Phoenix applications are configured.

  This can include things like missing headers,
  insecure cookies, and more.

  If you wish to learn more about the specific vulnerabilities
  found within the Configuration category, you may run the
  following commands to find out more:

            $ mix sobelow -d Config.CSP
            $ mix sobelow -d Config.CSRF
            $ mix sobelow -d Config.CSRFRoute
            $ mix sobelow -d Config.CSWH
            $ mix sobelow -d Config.Headers
            $ mix sobelow -d Config.Secrets
            $ mix sobelow -d Config.HTTPS
            $ mix sobelow -d Config.HSTS

  Configuration checks of all types can be ignored with the
  following command:

      $ mix sobelow -i Config
  """

  alias Sobelow.Config.CSP
  alias Sobelow.Config.CSRF
  alias Sobelow.Config.CSRFRoute
  alias Sobelow.Config.CSWH
  alias Sobelow.Config.Headers
  alias Sobelow.Parse

  @submodules [
    Sobelow.Config.CSRF,
    Sobelow.Config.CSRFRoute,
    Sobelow.Config.Headers,
    Sobelow.Config.CSP,
    Sobelow.Config.Secrets,
    Sobelow.Config.HTTPS,
    Sobelow.Config.HSTS,
    Sobelow.Config.CSWH
  ]

  use Sobelow.FindingType
  @skip_files ["dev.exs", "test.exs", "dev.secret.exs", "test.secret.exs"]

  def fetch(root, router, endpoints) do
    allowed = Sobelow.allowed_checks(__MODULE__, @submodules)
    ignored_files = Sobelow.get_env(:ignored_files) || []

    dir_path = root <> "config/"

    configs =
      case File.ls(dir_path) do
        {:ok, files} ->
          files
          |> Enum.filter(&(Path.extname(&1) == ".exs"))
          |> Enum.map(&(dir_path <> &1))
          |> Sobelow.Scan.discover(&(not want_to_scan?(&1, ignored_files)))
          |> Enum.filter(&want_to_scan?(&1, ignored_files))
          |> Enum.map(&Path.basename/1)

        {:error, :enoent} ->
          []

        {:error, reason} ->
          IO.puts(
            :stderr,
            "Could not read #{dir_path}: #{:file.format_error(reason)}; skipping config files."
          )

          []
      end

    Enum.each(allowed, fn mod ->
      cond do
        mod in [CSRF, CSRFRoute, Headers, CSP] ->
          Enum.each(router, fn path ->
            apply(mod, :run, [relative_path(path, root)])
          end)

        mod in [CSWH] ->
          Enum.each(endpoints, fn path ->
            apply(mod, :run, [relative_path(path, root)])
          end)

        File.dir?(dir_path) ->
          apply(mod, :run, [dir_path, configs])

        true ->
          nil
      end
    end)
  end

  defp want_to_scan?(conf, ignored_files) do
    Path.extname(conf) === ".exs" && !Enum.member?(@skip_files, Path.basename(conf)) &&
      !Enum.member?(ignored_files, Path.expand(conf))
  end

  defp relative_path(path, root) do
    path = Path.relative_to(path, Path.expand(root))

    case Path.type(path) do
      :absolute -> path
      _ -> root <> path
    end
  end

  def get_configs_by_file(secret, file) do
    if File.exists?(file) do
      get_configs(secret, file)
    else
      []
    end
  end

  # Config utils

  def get_pipelines(filepath) do
    filepath
    |> get_pipelines_with_skips()
    |> Enum.map(fn {pipeline, _skips} -> pipeline end)
  end

  def get_unskipped_pipelines(filepath, check_mod) do
    filepath
    |> get_pipelines_with_skips()
    |> Enum.reject(fn {_pipeline, skips} -> skipped?(skips, check_mod) end)
    |> Enum.map(fn {pipeline, _skips} -> pipeline end)
  end

  defp get_pipelines_with_skips(filepath) do
    filepath
    |> Parse.ast()
    |> Parse.get_pipelines_with_skips()
  end

  # A pipeline skip matches either the specific check (`Config.CSRF`) or the
  # parent module (`Config`), which suppresses every Config check on that
  # pipeline. This mirrors `-i Config`, which drops the whole Config group.
  defp skipped?(skips, check_mod) do
    Sobelow.get_env(:skip) &&
      Enum.any?(skips, fn skip ->
        mod = Sobelow.get_mod(skip)
        mod == check_mod || mod == __MODULE__
      end)
  end

  def get_plug_list(block) do
    case block do
      {:__block__, _, list} -> list
      {_, _, _} = list -> [list]
      _ -> []
    end
    |> Enum.filter(fn
      {:plug, _, _} -> true
      _ -> false
    end)
  end

  def vuln_pipeline?({:pipeline, _, [_name, [do: block]]}, :csrf) do
    plugs = get_plug_list(block)
    has_csrf? = Enum.any?(plugs, &plug?(&1, :protect_from_forgery))
    has_session? = Enum.any?(plugs, &plug?(&1, :fetch_session))

    has_session? and not has_csrf?
  end

  def vuln_pipeline?({:pipeline, _, [_name, [do: block]]}, :headers) do
    plugs = get_plug_list(block)
    has_headers? = Enum.any?(plugs, &plug?(&1, :put_secure_browser_headers))
    accepts = Enum.find_value(plugs, &get_plug_accepts/1)

    !has_headers? && is_list(accepts) && Enum.member?(accepts, "html")
  end

  def get_plug_accepts({:plug, _, [:accepts, {:sigil_w, _, opts}]}), do: parse_accepts(opts)
  def get_plug_accepts({:plug, _, [:accepts, accepts]}), do: accepts
  def get_plug_accepts(_), do: []

  def parse_accepts([{:<<>>, _, [accepts | _]}, []]), do: String.split(accepts, " ")

  def plug?({:plug, _, [type]}, type), do: true
  def plug?({:plug, _, [type, _]}, type), do: true
  def plug?(_, _), do: false

  def get_fuzzy_configs(key, filepath) do
    ast = Parse.ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &extract_fuzzy_configs(&1, &2, key))
    acc
  end

  def get_configs(key, filepath) do
    ast = Parse.ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &extract_configs(&1, &2, key))
    acc
  end

  @doc false
  def effective_app_configs(filepath) do
    ast = Parse.ast(filepath)

    ast |> effective_configs(%{}, false) |> Map.values()
  end

  @doc false
  def effective_endpoint_config(key, filepath, endpoint_module) do
    if File.regular?(filepath) do
      filepath
      |> Parse.ast()
      |> effective_configs(%{}, false)
      |> Enum.find_value(:error, fn
        {{_app, ^endpoint_module}, options} -> Keyword.fetch(options, key)
        _ -> nil
      end)
    else
      :error
    end
  end

  defp effective_configs({:config, _, opts}, groups, conditional?) when is_list(opts) do
    case app_config(opts) do
      {app, module, options} ->
        if scanned_app?(app) do
          options =
            if conditional?,
              do: Enum.map(options, fn {key, _} -> {key, {:__sobelow_unknown__, [], []}} end),
              else: options

          Map.update(groups, {app, module}, options, &merge_options(&1, options))
        else
          groups
        end

      nil ->
        groups
    end
  end

  defp effective_configs({kind, _, args}, groups, conditional?) when is_list(args) do
    conditional? =
      conditional? or kind in [:if, :unless, :case, :cond, :for, :with, :try, :fn, :def, :defp]

    effective_configs(args, groups, conditional?)
  end

  defp effective_configs(nodes, groups, conditional?) when is_list(nodes),
    do: Enum.reduce(nodes, groups, &effective_configs(&1, &2, conditional?))

  defp effective_configs({_key, value}, groups, conditional?),
    do: effective_configs(value, groups, conditional?)

  defp effective_configs(_, groups, _conditional?), do: groups

  defp app_config([app, options]) when is_atom(app) and is_list(options) do
    if Keyword.keyword?(options), do: {app, nil, options}
  end

  defp app_config([app, {:__aliases__, _, module}, options])
       when is_atom(app) and is_list(options) do
    if List.last(module) == :Endpoint and Keyword.keyword?(options), do: {app, module, options}
  end

  defp app_config(_), do: nil

  defp merge_options(previous, current) do
    Keyword.merge(previous, current, fn _key, old, new ->
      if is_list(old) and is_list(new) and Keyword.keyword?(old) and Keyword.keyword?(new),
        do: merge_options(old, new),
        else: new
    end)
  end

  @doc false
  def setting_status(value) when value in [false, nil], do: :disabled
  def setting_status(true), do: :enabled

  def setting_status(value) when is_list(value) do
    if Keyword.keyword?(value), do: :enabled, else: :unknown
  end

  def setting_status(_), do: :unknown

  @doc false
  def hsts_status(value) do
    case setting_status(value) do
      :enabled when is_list(value) ->
        case Keyword.get(value, :hsts, true) do
          false -> :disabled
          true -> :enabled
          _ -> :unknown
        end

      status ->
        status
    end
  end

  @doc false
  # `https` and `force_ssl` apply to the application being scanned. A setting
  # for another OTP app or an unrelated named module must not satisfy them.
  # Keep the historical two-argument `config :app, key: value` form too.
  def get_app_configs(key, filepath) do
    ast = Parse.ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &extract_app_configs(&1, &2, key))
    acc
  end

  @doc false
  def get_endpoint_configs(key, filepath, endpoint_module) do
    if File.regular?(filepath) do
      ast = Parse.ast(filepath)

      {_, configs} =
        Macro.prewalk(ast, [], fn
          {:config, _, [app, {:__aliases__, _, ^endpoint_module}, options]} = node, acc
          when is_atom(app) and is_list(options) ->
            if scanned_app?(app) and Keyword.keyword?(options) do
              case Keyword.fetch(options, key) do
                {:ok, value} -> {node, [{node, key, value} | acc]}
                :error -> {node, acc}
              end
            else
              {node, acc}
            end

          node, acc ->
            {node, acc}
        end)

      configs
    else
      []
    end
  end

  defp extract_app_configs({:config, _, opts} = ast, acc, key) when is_list(opts) do
    value =
      case opts do
        [app, config] when is_atom(app) and is_list(config) ->
          if scanned_app?(app) and Keyword.keyword?(config),
            do: Keyword.fetch(config, key),
            else: :error

        [app, {:__aliases__, _, module}, config]
        when is_atom(app) and is_list(module) and is_list(config) ->
          if scanned_app?(app) and List.last(module) == :Endpoint and Keyword.keyword?(config),
            do: Keyword.fetch(config, key),
            else: :error

        _ ->
          :error
      end

    case value do
      {:ok, value} -> {ast, [{ast, key, value} | acc]}
      :error -> {ast, acc}
    end
  end

  defp extract_app_configs(ast, acc, _key), do: {ast, acc}

  defp scanned_app?(app) do
    case Sobelow.get_env(:app_name) do
      nil -> true
      name -> Atom.to_string(app) == name
    end
  end

  @doc false
  def enabled_config?({_, _, value}), do: value not in [false, nil]

  @doc false
  def hsts_enabled?({_, _, value}) do
    enabled_config?({nil, nil, value}) and
      (not is_list(value) or
         (Keyword.keyword?(value) and Keyword.get(value, :hsts, true) != false))
  end

  defp extract_fuzzy_configs({:config, _, opts} = ast, acc, key) when is_list(opts) do
    opt = List.last(opts)
    vals = if Keyword.keyword?(opt), do: fuzzy_keyword_get(opt, key), else: nil

    if is_nil(vals) do
      {ast, acc}
    else
      {ast, [{ast, vals} | acc]}
    end
  end

  defp extract_fuzzy_configs(ast, acc, _key) do
    {ast, acc}
  end

  defp extract_configs({:config, _, opts} = ast, acc, key) when is_list(opts) do
    opt = List.last(opts)
    val = if Keyword.keyword?(opt), do: Keyword.get(opt, key), else: nil

    if is_nil(val) do
      {ast, acc}
    else
      {ast, [{ast, key, val} | acc]}
    end
  end

  defp extract_configs(ast, acc, _key) do
    {ast, acc}
  end

  defp fuzzy_keyword_get(opt, key) do
    keys = Keyword.keys(opt)

    Enum.map(keys, fn k ->
      if is_atom(k) && k != :secret_key_base do
        s = Atom.to_string(k) |> String.downcase()
        if String.contains?(s, key), do: {k, Keyword.get(opt, k)}
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  def get_version(filepath) do
    ast = Parse.ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &get_version(&1, &2))
    acc
  end

  def get_version({:@, _, nil} = ast, acc), do: {ast, acc}
  def get_version({:@, _, [{:version, _, [vsn]}]}, _acc) when is_binary(vsn), do: {vsn, vsn}
  def get_version(ast, acc), do: {ast, acc}

  def details do
    @moduledoc
  end
end
