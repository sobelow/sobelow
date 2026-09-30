defmodule Sobelow.Scan.Discovery do
  @moduledoc false

  alias Sobelow.Parse
  alias Sobelow.Utils

  def prepare(project_root, categories) do
    app_name = Utils.get_app_name(project_root <> "mix.exs")
    if !is_binary(app_name), do: file_error()

    # Older Phoenix apps split sources between web/ and lib/.
    phx_post_1_2? = !File.dir?(project_root <> "web")

    lib_root =
      if phx_post_1_2? do
        project_root <> "lib"
      else
        project_root <> "web"
      end

    ignored = Sobelow.get_ignored()
    allowed = categories -- ignored

    # Prepare source and template metadata before checks emit findings.
    root_meta_files = get_meta_files(lib_root)
    template_meta_files = get_meta_templates(lib_root)

    {libroot_meta_files, tmp_default_router} =
      if phx_post_1_2? do
        {[], ""}
      else
        libroot_meta_files = get_meta_files(project_root <> "lib")
        default_router = project_root <> "/web/router.ex"

        {libroot_meta_files, default_router}
      end

    extra_meta_files =
      if Sobelow.get_env(:include_scripts) do
        ["scripts", "priv"]
        |> Enum.map(&(project_root <> &1))
        |> Enum.filter(&File.dir?/1)
        |> Enum.flat_map(&get_meta_files/1)
      else
        []
      end

    if root_meta_files == [] and libroot_meta_files == [] and extra_meta_files == [] do
      raise Sobelow.ScanError,
            "No source files were found under the scan root. Check --root and source path options."
    end

    default_router = get_router(tmp_default_router, phx_post_1_2?)

    {routers, endpoints} =
      get_phoenix_files(root_meta_files ++ libroot_meta_files, default_router)

    if Enum.empty?(routers), do: no_router()

    %{
      app_name: app_name,
      allowed: allowed,
      files: root_meta_files ++ libroot_meta_files ++ extra_meta_files,
      templates: template_meta_files,
      routers: routers,
      endpoints: endpoints
    }
  end

  # CLI options use strings; config files can use atoms.
  defp router_disabled?, do: Sobelow.get_env(:router) in [:none, ":none"]

  defp get_router(tmp_default_router, phx_post_1_2?) do
    if router_disabled?() do
      ""
    else
      do_get_router(tmp_default_router, phx_post_1_2?)
    end
  end

  defp do_get_router("", true) do
    case Sobelow.get_env(:router) do
      nil -> ""
      "" -> ""
      router -> Path.expand(router, Sobelow.get_env(:root))
    end
  end

  defp do_get_router(tmp_default_router, _) do
    case Sobelow.get_env(:router) do
      nil -> Path.expand(tmp_default_router)
      "" -> Path.expand(tmp_default_router)
      router -> Path.expand(router, Sobelow.get_env(:root))
    end
  end

  defp get_phoenix_files(meta_files, router) do
    phoenix_files =
      Enum.reduce(meta_files, %{routers: [], endpoints: []}, fn meta_file, acc ->
        cond do
          meta_file.router? ->
            Map.update!(acc, :routers, &[meta_file.file_path | &1])

          meta_file.is_endpoint? ->
            Map.update!(acc, :endpoints, &[meta_file.file_path | &1])

          true ->
            acc
        end
      end)

    uniq_phoenix_files =
      if File.exists?(router) do
        Sobelow.Scan.discover([router], fn _ -> false end)

        Map.update!(phoenix_files, :routers, fn routers ->
          Enum.uniq(routers ++ [router])
        end)
      else
        phoenix_files
      end

    {uniq_phoenix_files.routers, uniq_phoenix_files.endpoints}
  end

  defp get_meta_templates(root) do
    ignored_files = Sobelow.get_env(:ignored_files)

    Utils.template_files(root)
    |> Sobelow.Scan.discover(&ignored_file?(&1, ignored_files))
    |> Enum.reject(&ignored_file?(&1, ignored_files))
    |> Sobelow.Scan.map(&get_template_meta/1)
    |> Map.new()
  end

  defp get_template_meta(filename) do
    meta_funs = Parse.get_meta_template_funs(filename)
    raw = meta_funs.raw
    ast = meta_funs.ast
    filename = Utils.normalize_path(filename)

    {
      filename,
      %{
        filename: filename,
        raw: raw,
        ast: [ast],
        controller?: false
      }
    }
  end

  defp get_meta_files(root) do
    ignored_files = Sobelow.get_env(:ignored_files)

    Utils.all_files(root)
    |> Sobelow.Scan.discover(&ignored_file?(&1, ignored_files))
    |> Enum.reject(&ignored_file?(&1, ignored_files))
    |> Sobelow.Scan.map(&get_file_meta/1)
  end

  defp get_file_meta(filename) do
    # Warn about malformed skip comments once during preparation.
    ast = Parse.ast_with_skip_warnings(filename)
    {meta_funs, contexts} = Parse.file_metadata(ast)
    use_funs = meta_funs.use_funs
    import_funs = meta_funs.import_funs

    lexical = Sobelow.Lexical.functions(ast)

    scan_contexts =
      Enum.map(contexts, fn context ->
        functions =
          context.def_funs
          |> combine_skips()
          |> Enum.map(fn
            {fun, _skips} = skipped -> {skipped, Map.get(lexical, fun)}
            fun -> {fun, Map.get(lexical, fun)}
          end)

        %{
          functions: functions,
          controller?: Utils.controller?(context.use_funs),
          imports_ecto_sql?: Utils.imports?(context.import_funs, [:Ecto, :Adapters, :SQL]),
          ecto_repo?: Utils.uses?(context.use_funs, [:Ecto, :Repo])
        }
      end)

    %{
      filename: Utils.normalize_path(filename),
      file_path: Path.expand(filename),
      scan_contexts: scan_contexts,
      controller?: Utils.controller?(use_funs),
      router?: Utils.router?(use_funs),
      is_endpoint?: Utils.endpoint?(use_funs),
      # An unqualified `query/3` only means Ecto's if the file imported it, and an
      # unqualified `query/1` only means a repo's if the file is one. Without that
      # evidence a bare `query(...)` is somebody's own function.
      imports_ecto_sql?: Utils.imports?(import_funs, [:Ecto, :Adapters, :SQL]),
      ecto_repo?: Utils.uses?(use_funs, [:Ecto, :Repo])
    }
  end

  defp combine_skips([]), do: []

  defp combine_skips([head | tail] = funs) do
    if Sobelow.get_env(:skip), do: combine_skips(head, tail), else: funs
  end

  defp combine_skips(prev, []), do: [prev]
  defp combine_skips(prev, [{:@, _, [{:sobelow_skip, _, [skips]}]} | []]), do: [{prev, skips}]

  defp combine_skips(prev, [{:@, _, [{:sobelow_skip, _, [skips]}]}, h | t]) do
    [{prev, skips} | combine_skips(h, t)]
  end

  defp combine_skips(prev, [h | t]) do
    [prev | combine_skips(h, t)]
  end

  defp no_router do
    message = """
    WARNING: Sobelow cannot find the router. If this is a Phoenix application
    please use the `--router` flag to specify the router's location.
    """

    if !router_disabled?(), do: IO.puts(:stderr, message)

    # The router checks are dropped either way — without a router there is
    # nothing for them to inspect.
    ignored = Sobelow.get_env(:ignored)

    Application.put_env(
      :sobelow,
      :ignored,
      ignored ++ ["Config.CSRF", "Config.CSRFRoute", "Config.Headers", "Config.CSP"]
    )
  end

  defp file_error do
    message = """
    This does not appear to be a Phoenix application. If this is an Umbrella application,
    each application should be scanned separately.
    """

    raise Sobelow.ScanError, message
  end

  defp ignored_file?(filename, ignored_files) do
    Enum.any?(ignored_files, fn ignored_file ->
      String.ends_with?(ignored_file, filename)
    end)
  end
end
