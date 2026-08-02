defmodule Mix.Tasks.Sobelow do
  use Mix.Task

  @moduledoc """
  Sobelow is a static analysis tool for discovering
  vulnerabilities in Phoenix applications.

  This tool should be run in the root of the project directory
  with the following command:

      mix sobelow

  ## Command line options

  * `--root -r` - Specify application root directory
  * `--verbose -v` - Print vulnerable code snippets
  * `--ignore -i` - Ignore modules
  * `--ignore-files` - Ignore files
  * `--details -d` - Get module details
  * `--all-details` - Get all module details
  * `--private` - Skip update checks
  * `--strict` - Exit when bad syntax is encountered
  * `--mark-skip-all` - Mark all printed findings as skippable
  * `--clear-skip` - Clear configuration added by `--mark-skip-all`
  * `--legacy-skips` - Append to `.sobelow-skips` instead of rewriting it sorted
  * `--skip` - Skip functions/Phoenix pipelines flagged with `#sobelow_skip` or tagged with `--mark-skip-all`
  * `--router` - Specify router location
  * `--no-router` - Scan a project that has no Phoenix router, suppressing the
  "cannot find the router" warning. Equivalent to `--router :none`
  * `--exit` - Return non-zero exit status
  * `--threshold` - Only return findings at or above a given confidence level
  * `--format` - Specify findings output format
  * `--quiet` - Return no output if there are no findings
  * `--compact` - Minimal, single-line findings
  * `--save-config` - Generates a configuration file based on command line options
  * `--[no-]config` - Run Sobelow with or without the configuration file.
  * `--version` - Output current version of Sobelow

  ## Ignoring modules

  If specific modules, or classes of modules are not relevant
  to the scan, it is possible to ignore them with a
  comma-separated list.

      mix sobelow -i XSS.Raw,Traversal

  ## Supported modules

  * XSS
  * XSS.Raw
  * XSS.SendResp
  * XSS.ContentType
  * XSS.HTML
  * SQL
  * SQL.Query
  * SQL.Stream
  * Config
  * Config.CSRF
  * Config.Headers
  * Config.CSP
  * Config.HTTPS
  * Config.HSTS
  * Config.Secrets
  * Config.CSWH
  * Vuln
  * Vuln.CookieRCE
  * Vuln.HeaderInject
  * Vuln.PlugNull
  * Vuln.Redirect
  * Vuln.Coherence
  * Vuln.Ecto
  * Traversal
  * Traversal.SendFile
  * Traversal.FileModule
  * Traversal.SendDownload
  * Misc
  * Misc.BinToTerm
  * Misc.FilePath
  * RCE.EEx
  * RCE.CodeModule
  * CI
  * CI.System
  * CI.OS
  * DOS
  * DOS.StringToAtom
  * DOS.ListToAtom
  * DOS.BinToAtom

  """
  @switches [
    verbose: :boolean,
    root: :string,
    ignore: :string,
    ignore_files: :string,
    details: :string,
    all_details: :boolean,
    private: :boolean,
    strict: :boolean,
    diff: :string,
    skip: :boolean,
    mark_skip_all: :boolean,
    clear_skip: :boolean,
    legacy_skips: :boolean,
    router: :string,
    no_router: :boolean,
    exit: :string,
    format: :string,
    config: :boolean,
    save_config: :boolean,
    quiet: :boolean,
    compact: :boolean,
    flycheck: :boolean,
    out: :string,
    threshold: :string,
    version: :boolean
  ]

  @aliases [v: :verbose, r: :root, i: :ignore, d: :details, f: :format]

  # These pick what Sobelow *does* instead of configuring a scan, and every one
  # of them ends the run before a scan happens. `.sobelow-conf` is read
  # automatically and committed to the repository, so honouring one from the
  # file means a checked-in file can stop the scanner from ever scanning —
  # `version: true` prints the version and exits 0, which a CI gate reads as a
  # clean scan. They are accepted on the command line only.
  @cli_only_actions [:version, :details, :all_details, :save_config, :diff]

  # For escript entry
  def main(argv) do
    run(argv)
  end

  def run(argv) do
    {opts, _, _} = OptionParser.parse(argv, aliases: @aliases, switches: @switches)

    root = Keyword.get(opts, :root, ".")
    config = Keyword.get(opts, :config, true)
    conf_file = root <> "/.sobelow-conf"
    conf_file? = config && File.exists?(conf_file)

    opts =
      if is_nil(Keyword.get(opts, :exit)) && Enum.member?(argv, "--exit") do
        [{:exit, "low"} | opts]
      else
        opts
      end

    opts =
      if conf_file? do
        # CLI args take precedence
        Keyword.merge(config_settings(conf_file), opts)
      else
        opts
      end

    {verbose, diff, details, private, strict, skip, mark_skip_all, clear_skip, router, exit_on,
     format, ignored, ignored_files, all_details, out, threshold, version} = get_opts(opts, root)

    set_env(:verbose, verbose)

    if with_code = Keyword.get(opts, :with_code) do
      Mix.Shell.IO.info("WARNING: --with-code is deprecated, please use --verbose instead.\n")
      set_env(:verbose, with_code)
    end

    set_env(:root, root)
    set_env(:details, details)
    set_env(:private, private)
    set_env(:strict, strict)
    set_env(:skip, skip)
    set_env(:mark_skip_all, mark_skip_all)
    set_env(:clear_skip, clear_skip)
    set_env(:legacy_skips, Keyword.get(opts, :legacy_skips, false))
    set_env(:router, router)
    set_env(:exit_on, exit_on)
    set_env(:format, format)
    set_env(:ignored, ignored)
    set_env(:ignored_files, ignored_files)
    set_env(:out, out)
    set_env(:threshold, threshold)
    set_env(:version, version)

    save_config = Keyword.get(opts, :save_config)

    if function_exported?(Mix, :ensure_application!, 1) do
      Mix.ensure_application!(:ssl)
      Mix.ensure_application!(:inets)
    end

    cond do
      diff ->
        run_diff(argv)

      !is_nil(save_config) ->
        Sobelow.save_config(conf_file)

      !is_nil(all_details) ->
        Sobelow.all_details()

      !is_nil(details) ->
        Sobelow.details()

      version ->
        Sobelow.version()

      true ->
        Sobelow.run()
    end
  end

  # This diff check is strictly used for testing/debugging and
  # isn't meant for general use.
  #
  # Useful for comparing the output of two different runs of Sobelow
  def run_diff(argv) do
    diff_idx = Enum.find_index(argv, fn i -> i === "--diff" end)
    {_, list} = List.pop_at(argv, diff_idx)
    {diff_target, list} = List.pop_at(list, diff_idx)
    args = Enum.join(list, " ")
    diff_target = to_string(diff_target)
    System.shell("mix sobelow #{args} > sobelow.tempdiff")
    {diff, _} = System.shell("diff sobelow.tempdiff #{diff_target}")
    IO.puts(diff)
  end

  def set_env(key, value) do
    Application.put_env(:sobelow, key, value)
  end

  @doc false
  def read_config_file(conf_file) do
    with {:ok, contents} <- File.read(conf_file),
         {:ok, opts} <- Code.string_to_quoted(contents),
         {:ok, opts} <- validate_config(opts) do
      {:ok, opts}
    else
      _ -> {:error, config_file_error(conf_file)}
    end
  end

  # An empty (or comment-only) config file is a benign state — `touch
  # .sobelow-conf`, a truncated write — and parses to an empty block rather than
  # to a keyword list. Since v0.14.1 reads the file automatically, treating that
  # as fatal would break scans over a file that asks for nothing. Contents we
  # cannot make sense of are still an error, so a scan never silently runs with
  # configuration the user believed was applied.
  defp validate_config({:__block__, _, []}), do: {:ok, []}

  defp validate_config(opts) do
    if Keyword.keyword?(opts), do: {:ok, opts}, else: :error
  end

  @doc false
  # The settings from `.sobelow-conf`, with any command-line action dropped.
  #
  # A value that would not have changed anything is dropped in silence: every
  # release up to v0.14.1 wrote `version: false` into the file that
  # `--save-config` generated, so warning about it would fire for a great many
  # existing projects that have nothing wrong with them.
  def config_settings(conf_file) do
    conf_file
    |> load_config_file()
    |> Enum.reject(fn {key, value} ->
      if key in @cli_only_actions do
        if value, do: warn_ignored_action(conf_file, key)
        true
      else
        false
      end
    end)
  end

  defp warn_ignored_action(conf_file, key) do
    Sobelow.IO.warn("""
    Ignoring `#{key}` in #{conf_file}.

    `--#{String.replace(to_string(key), "_", "-")}` chooses what Sobelow does \
    rather than configuring a scan, and a configuration file that sets one \
    stops the scan from running at all. Remove it from the file and pass it on \
    the command line when you want it.
    """)
  end

  defp load_config_file(conf_file) do
    case read_config_file(conf_file) do
      {:ok, opts} ->
        opts

      {:error, message} ->
        Sobelow.IO.error(message)
        System.halt(1)
    end
  end

  defp config_file_error(conf_file) do
    """
    Could not read #{conf_file}.

    The configuration file must contain a single keyword list, for example:

        [exit: :low, format: "txt", ignore: ["XSS.Raw"], verbose: false]

    Regenerate it with `mix sobelow --save-config`, or pass `--no-config` to
    ignore it for this run.
    """
  end

  defp get_opts(opts, root) do
    verbose = Keyword.get(opts, :verbose, false)
    details = Keyword.get(opts, :details, nil)
    all_details = Keyword.get(opts, :all_details)
    private = Keyword.get(opts, :private, false)
    strict = Keyword.get(opts, :strict, false)
    diff = Keyword.get(opts, :diff, false)
    skip = Keyword.get(opts, :skip, false)
    mark_skip_all = Keyword.get(opts, :mark_skip_all, false)
    clear_skip = Keyword.get(opts, :clear_skip, false)
    # `--no-router` is the discoverable spelling of `--router :none`. Normalising
    # it here keeps `:router` the single source of truth, so `--save-config`
    # records it and a `.sobelow-conf` can express it too.
    router =
      if Keyword.get(opts, :no_router, false),
        do: :none,
        else: Keyword.get(opts, :router)

    out = Keyword.get(opts, :out)
    version = Keyword.get(opts, :version, false)

    exit_on =
      Keyword.get(opts, :exit, "None")
      |> to_string()
      |> String.downcase()
      |> case do
        "high" -> :high
        "medium" -> :medium
        "low" -> :low
        _ -> false
      end

    format =
      cond do
        Keyword.get(opts, :quiet) -> "quiet"
        Keyword.get(opts, :compact) -> "compact"
        Keyword.get(opts, :flycheck) -> "flycheck"
        true -> Keyword.get(opts, :format, "txt") |> String.downcase()
      end

    format = out_format(out, format)

    ignored =
      case Keyword.get(opts, :ignore, []) do
        ignore_str when is_binary(ignore_str) -> String.split(ignore_str, ",")
        ignore -> ignore
      end

    ignored_files =
      case Keyword.get(opts, :ignore_files, []) do
        ignore_files when is_list(ignore_files) ->
          Enum.map(ignore_files, &Path.expand(&1, root))

        ignore_files_str when is_binary(ignore_files_str) ->
          for i <- String.split(ignore_files_str, ",", trim: true), do: Path.expand(i, root)
      end

    threshold =
      Keyword.get(opts, :threshold, "low")
      |> to_string()
      |> String.downcase()
      |> case do
        "high" -> :high
        "medium" -> :medium
        _ -> :low
      end

    {verbose, diff, details, private, strict, skip, mark_skip_all, clear_skip, router, exit_on,
     format, ignored, ignored_files, all_details, out, threshold, version}
  end

  # Future updates will include format hinting based on the outfile name. Additional output
  # formats will also be added.
  defp out_format(nil, format), do: format
  defp out_format("", format), do: format

  defp out_format(_out, format) do
    if format in ["json", "quiet", "sarif"] do
      format
    else
      "json"
    end
  end
end
