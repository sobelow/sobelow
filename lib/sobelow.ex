defmodule Sobelow do
  @moduledoc """
  Sobelow is a static analysis tool for discovering
  vulnerabilities in Phoenix applications.
  """
  @v Mix.Project.config()[:version]
  @home "~/.sobelow"
  @vsncheck "sobelow-vsn-check"
  @skips ".sobelow-skips"
  @submodules [
    Sobelow.XSS,
    Sobelow.SQL,
    Sobelow.Traversal,
    Sobelow.RCE,
    Sobelow.Misc,
    Sobelow.Config,
    Sobelow.CI,
    Sobelow.DOS,
    Sobelow.Vuln
  ]

  alias Sobelow.Config
  alias Sobelow.Finding
  alias Sobelow.FindingLog
  alias Sobelow.Fingerprint
  alias Sobelow.IO, as: MixIO
  alias Sobelow.MetaLog
  alias Sobelow.Parse
  alias Sobelow.Utils
  alias Sobelow.Vuln

  def run do
    project_root = get_env(:root) <> "/"
    version_check()

    app_name = Utils.get_app_name(project_root <> "mix.exs")
    if !is_binary(app_name), do: file_error()

    # If web_root ends with the app_name, then it is the
    # more recent version of Phoenix. Meaning, all files are
    # in the lib directory, so we don't need to re-scan
    # lib_root separately.
    phx_post_1_2? = !File.dir?(project_root <> "web")

    lib_root =
      if phx_post_1_2? do
        project_root <> "lib"
      else
        project_root <> "web"
      end

    ignored = get_ignored()
    allowed = @submodules -- ignored

    # Pulling out function definitions before kicking
    # off the test pipeline to avoid dumping warning
    # messages into the findings output.
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

    default_router = get_router(tmp_default_router, phx_post_1_2?)

    {routers, endpoints} =
      get_phoenix_files(root_meta_files ++ libroot_meta_files, default_router)

    if Enum.empty?(routers), do: no_router()

    init_state(project_root, template_meta_files)

    if get_env(:clear_skip), do: clear_skip(project_root)

    # This is where the core testing-pipeline starts.
    #
    # - Print banner
    # - Check configuration
    # - Remove config check from "allowed" modules
    # - Scan funcs from the root
    # - Scan funcs from the libroot
    if format() not in ["quiet", "compact", "flycheck", "json"],
      do: IO.puts(:stderr, print_banner())

    Application.put_env(:sobelow, :app_name, app_name)

    # Config and Vuln are each a single unit of work, so there is nothing to
    # spread across schedulers. Running them directly keeps them off
    # `Task.async_stream/3`, whose default 5s timeout would otherwise abort a
    # scan of a project large enough for either to run long.
    if Enum.member?(allowed, Config), do: Config.fetch(project_root, routers, endpoints)
    if Enum.member?(allowed, Vuln), do: Vuln.get_vulns(project_root)

    allowed = allowed -- [Config, Vuln]

    root_and_libroot_tasks =
      [root_meta_files, libroot_meta_files]
      |> Enum.concat()
      |> Task.async_stream(
        fn meta_file ->
          meta_file.def_funs
          |> combine_skips()
          |> Enum.each(&get_fun_vulns(&1, meta_file, project_root, allowed))
        end,
        timeout: :infinity
      )

    xss_tasks =
      if Sobelow.XSS in allowed do
        Task.async_stream(
          template_meta_files,
          fn {_, meta_file} -> Sobelow.XSS.get_template_vulns(meta_file) end,
          timeout: :infinity
        )
      end

    [root_and_libroot_tasks, xss_tasks]
    |> Enum.map(&List.wrap/1)
    |> Enum.concat()
    |> Enum.each(&Stream.run/1)

    if format() != "txt" do
      print_output()
    else
      FindingLog.print_txt()
      IO.puts(:stderr, "... SCAN COMPLETE ...\n")
    end

    if get_env(:mark_skip_all), do: mark_skip_all(project_root)

    exit_with_status()
  end

  defp init_state(project_root, template_meta_files) do
    FindingLog.start_link()
    MetaLog.start_link()
    Fingerprint.start_link()
    load_ignored_fingerprints(project_root)
    MetaLog.add_templates(template_meta_files)
  end

  defp print_output do
    details =
      case output_format() do
        "json" ->
          FindingLog.json(@v)

        "quiet" ->
          FindingLog.quiet()

        "sarif" ->
          FindingLog.sarif(@v)

        _ ->
          nil
      end

    if !is_nil(details) do
      print_std_or_file(details)
    end
  end

  defp print_std_or_file(details) do
    case get_env(:out) do
      nil -> IO.puts(details)
      "" -> IO.puts(details)
      out -> File.write(out, details)
    end
  end

  defp exit_with_status do
    exit_on = get_env(:exit_on)
    finding_logs = FindingLog.log()

    high_count = length(finding_logs[:high])
    medium_count = length(finding_logs[:medium])
    low_count = length(finding_logs[:low])

    status =
      case exit_on do
        :high ->
          if high_count > 0, do: 1

        :medium ->
          if high_count + medium_count > 0, do: 1

        :low ->
          if high_count + medium_count + low_count > 0, do: 1

        _ ->
          0
      end

    if exit_on && !is_nil(status) do
      System.halt(status)
    end
  end

  def details do
    mod =
      get_env(:details)
      |> get_mod

    if is_nil(mod) do
      MixIO.error("A valid module was not selected.")
    else
      apply(mod, :details, []) |> IO.puts()
    end
  end

  # `nil` means "print the default metadata block". A list means "print exactly
  # these headers", and an empty list therefore means "print none" — which is
  # what findings like `Config.HSTS` want, since they have no function, line, or
  # variable to report.
  def log_finding(finding, custom_metadata \\ nil)

  def log_finding(%Finding{} = finding, custom_metadata)
      when is_nil(custom_metadata) or is_list(custom_metadata) do
    do_log_finding(finding.type, finding, custom_metadata)
  end

  def log_finding(details, %Finding{} = finding) do
    do_log_finding(details, finding, nil)
  end

  defp do_log_finding(details, %Finding{} = finding, custom_metadata) do
    if loggable?(finding, finding.confidence) do
      Fingerprint.put(finding.fingerprint)
      FindingLog.add({details, finding, custom_metadata}, finding.confidence)
    end
  end

  def loggable?(%Finding{} = finding, severity) do
    legacy_skip = finding.legacy_fingerprint && Fingerprint.member?(finding.legacy_fingerprint)
    new_skip = finding.fingerprint && Fingerprint.member?(finding.fingerprint)

    !(get_env(:skip) && (new_skip || legacy_skip)) &&
      meets_threshold?(severity)
  end

  def all_details do
    @submodules
    |> Enum.map(&apply(&1, :details, []))
    |> List.flatten()
    |> Enum.each(&IO.puts(&1))
  end

  def rules do
    @submodules
    |> Enum.flat_map(&apply(&1, :rules, []))
  end

  def finding_modules do
    @submodules
    |> Enum.flat_map(&apply(&1, :finding_modules, []))
  end

  def save_config(conf_file) do
    conf = [
      exit: get_env(:exit_on),
      format: get_env(:format),
      ignore: get_env(:ignored),
      ignore_files: relative_ignored_files(),
      out: get_env(:out),
      private: get_env(:private),
      router: get_env(:router),
      skip: get_env(:skip),
      threshold: get_env(:threshold),
      verbose: get_env(:verbose),
      version: get_env(:version)
    ]

    yes? =
      if File.exists?(conf_file) do
        MixIO.yes?("The file .sobelow-conf already exists. Are you sure you want to overwrite?")
      else
        true
      end

    if yes? do
      File.write!(conf_file, inspect(conf, limit: :infinity, printable_limit: :infinity))
      MixIO.info("Updated .sobelow-conf")
    end
  end

  # `--ignore-files` values are expanded to absolute paths at parse time, but
  # `.sobelow-conf` is meant to be committed and shared, so store them relative
  # to the project root.
  defp relative_ignored_files do
    root = Utils.get_root() |> Path.expand()

    get_env(:ignored_files)
    |> Enum.map(&Path.relative_to(&1, root))
  end

  def meets_threshold?(severity) do
    threshold =
      case get_env(:threshold) do
        :high -> [:high]
        :medium -> [:high, :medium]
        _ -> [:high, :medium, :low]
      end

    severity in threshold
  end

  def format do
    case get_env(:format) do
      "sarif" -> "json"
      format -> format
    end
  end

  def output_format do
    get_env(:format)
  end

  def get_env(key) do
    Application.get_env(:sobelow, key)
  end

  defp print_banner do
    """
    ##############################################
    #                                            #
    #          Running Sobelow - v#{@v}         #
    #  Created by Griffin Byatt - @griffinbyatt  #
    #     NCC Group - https://nccgroup.trust     #
    #                                            #
    ##############################################
    """
  end

  defp get_router("", true) do
    case get_env(:router) do
      nil -> ""
      "" -> ""
      router -> Path.expand(router)
    end
  end

  defp get_router(tmp_default_router, _) do
    case get_env(:router) do
      nil -> tmp_default_router
      "" -> tmp_default_router
      router -> router
    end
    |> Path.expand()
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
        Map.update!(phoenix_files, :routers, fn routers ->
          Enum.uniq(routers ++ [router])
        end)
      else
        phoenix_files
      end

    {uniq_phoenix_files.routers, uniq_phoenix_files.endpoints}
  end

  defp get_meta_templates(root) do
    ignored_files = get_env(:ignored_files)

    Utils.template_files(root)
    |> Enum.reject(&ignored_file?(&1, ignored_files))
    |> Enum.map(&get_template_meta/1)
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
    ignored_files = get_env(:ignored_files)

    Utils.all_files(root)
    |> Enum.reject(&ignored_file?(&1, ignored_files))
    |> Enum.map(&get_file_meta/1)
  end

  defp get_file_meta(filename) do
    ast = Parse.ast(filename)
    meta_funs = Parse.get_meta_funs(ast)
    def_funs = meta_funs.def_funs
    use_funs = meta_funs.use_funs

    %{
      filename: Utils.normalize_path(filename),
      file_path: Path.expand(filename),
      def_funs: def_funs,
      controller?: Utils.controller?(use_funs),
      router?: Utils.router?(use_funs),
      is_endpoint?: Utils.endpoint?(use_funs)
    }
  end

  defp get_fun_vulns({fun, skips}, meta_file, web_root, mods) do
    skip_mods =
      skips
      |> Enum.map(&get_mod/1)

    Enum.each(mods -- skip_mods, fn mod ->
      params = [fun, meta_file, web_root, skip_mods]
      apply(mod, :get_vulns, params)
    end)
  end

  defp get_fun_vulns(fun, meta_file, web_root, mods) do
    get_fun_vulns({fun, []}, meta_file, web_root, mods)
  end

  defp combine_skips([]), do: []

  defp combine_skips([head | tail] = funs) do
    if get_env(:skip), do: combine_skips(head, tail), else: funs
  end

  defp combine_skips(prev, []), do: [prev]
  defp combine_skips(prev, [{:@, _, [{:sobelow_skip, _, [skips]}]} | []]), do: [{prev, skips}]

  defp combine_skips(prev, [{:@, _, [{:sobelow_skip, _, [skips]}]} | tail]) do
    [h | t] = tail
    [{prev, skips} | combine_skips(h, t)]
  end

  defp combine_skips(prev, rest) do
    [h | t] = rest
    [prev | combine_skips(h, t)]
  end

  defp no_router do
    message = """
    WARNING: Sobelow cannot find the router. If this is a Phoenix application
    please use the `--router` flag to specify the router's location.
    """

    IO.puts(:stderr, message)
    ignored = get_env(:ignored)

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

    MixIO.error(message)
    System.halt(0)
  end

  defp clear_skip(project_root) do
    cfile = project_root <> @skips

    if File.exists?(cfile) do
      File.rm!(cfile)
    end

    System.halt(0)
  end

  defp mark_skip_all(project_root) do
    cfile = project_root <> @skips

    case Fingerprint.new_skips() do
      [] ->
        nil

      new_fingerprints ->
        # Get all findings from the log to match fingerprints to finding details
        %{high: highs, medium: meds, low: lows} = FindingLog.log()
        all_findings = highs ++ meds ++ lows

        # Create a map of fingerprint -> finding for quick lookup
        fingerprint_to_finding =
          all_findings
          |> Enum.map(fn {_details, finding, _} -> {finding.fingerprint, finding} end)
          |> Map.new()

        # Build skip entries in new format: type,filename_line_n,hash
        skip_entries =
          new_fingerprints
          |> Enum.map(fn fingerprint ->
            case Map.get(fingerprint_to_finding, fingerprint) do
              %Finding{} = finding ->
                # Get relative filename (remove project root)
                filename =
                  Utils.get_root()
                  |> Utils.normalize_path()
                  |> (&String.replace_prefix(finding.filename, &1, "")).()
                  |> Utils.normalize_path()

                "#{finding.type},#{filename}:#{finding.vuln_line_no},#{fingerprint}"

              nil ->
                # Should not happen, each fingerprint should have a corresponding finding
                fingerprint
            end
          end)

        write_skips(cfile, skip_entries)
    end
  end

  defp write_skips(cfile, entries) do
    if get_env(:legacy_skips) do
      append_skips(cfile, entries)
    else
      rewrite_skips(cfile, entries)
    end
  end

  # The historical behaviour: never touch what is already in the file, only add
  # to the end of it. Kept behind `--legacy-skips` for anyone whose tooling
  # depends on the file being append-only.
  defp append_skips(cfile, entries) do
    {:ok, iofile} = :file.open(cfile, [:append])
    :file.write(iofile, ["\n", entries |> sort_skips() |> Enum.join("\n")])
    :file.close(iofile)
  end

  # Sorting only the newly appended entries leaves the file as a series of
  # independently sorted blocks, so the churn this avoids only holds for a file
  # written in one go. Merging with what is already there and rewriting keeps the
  # whole file ordered however many times it is regenerated.
  defp rewrite_skips(cfile, entries) do
    existing =
      case File.read(cfile) do
        {:ok, contents} -> contents |> String.split("\n") |> Enum.map(&String.trim/1)
        {:error, _} -> []
      end

    lines =
      (existing ++ entries)
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()
      |> sort_skips()

    File.write!(cfile, Enum.join(lines, "\n") <> "\n")
  end

  defp sort_skips(entries), do: Enum.sort_by(entries, &skip_sort_key/1)

  # Sorting the raw string would put line 10 before line 2, so an edit that
  # renumbers findings reshuffles the file — exactly the churn sorting is meant
  # to remove. Ordering on the parsed location keeps entries in place and lets
  # only their line numbers change.
  #
  # Comments are kept at the top, where a header note belongs. Bare fingerprints
  # are the pre-v0.14 format and sort last, since they carry no location to sort
  # on. Nothing is ever dropped: a rewrite preserves every line it found.
  defp skip_sort_key("#" <> _ = comment), do: {0, comment, "", 0, ""}

  defp skip_sort_key(entry) do
    case String.split(entry, ",") do
      [type, location, fingerprint] ->
        {file, line_no} = split_skip_location(location)
        {1, type, file, line_no, fingerprint}

      [fingerprint] ->
        {2, "", "", 0, fingerprint}

      _ ->
        {3, entry, "", 0, ""}
    end
  end

  defp split_skip_location(location) do
    segments = String.split(location, ":")

    case segments |> List.last() |> Integer.parse() do
      {line_no, ""} -> {segments |> Enum.drop(-1) |> Enum.join(":"), line_no}
      _ -> {location, 0}
    end
  end

  defp load_ignored_fingerprints(project_root) do
    cfile = project_root <> @skips

    if File.exists?(cfile) do
      {:ok, iofile} = :file.open(cfile, [:read])

      :file.read_line(iofile) |> load_ignored_fingerprints(iofile)
      :file.close(iofile)
    end
  end

  defp load_ignored_fingerprints({:ok, line}, iofile) do
    line_str = to_string(line) |> String.trim()

    # Parse line - could be old format (just hash) or new format (type,filename_line_n,hash)
    fingerprint =
      case String.split(line_str, ",") do
        [fingerprint] when fingerprint != "" ->
          # Old format: just the fingerprint hash
          fingerprint

        [_type, _filename_line_n, fingerprint] when fingerprint != "" ->
          # New format: type,filename_line_n,phash2 - extract phash2
          fingerprint

        _ ->
          # Invalid line, skip it
          nil
      end

    if fingerprint, do: Fingerprint.put_ignore(fingerprint)
    :file.read_line(iofile) |> load_ignored_fingerprints(iofile)
  end

  defp load_ignored_fingerprints(:eof, _), do: nil
  defp load_ignored_fingerprints(_, _), do: nil

  @doc false
  # `SOBELOW_HOME` overrides the *directory* the version-check timestamp is cached in.
  def version_check_file do
    (System.get_env("SOBELOW_HOME") || @home)
    |> Path.expand()
    |> Path.join(@vsncheck)
  end

  defp version_check do
    if get_env(:private) do
      nil
    else
      config = version_check_file()
      home = Path.dirname(config)

      # An unwritable home directory is not a reason to fail a scan.
      case File.mkdir_p(home) do
        :ok -> version_check(config)
        {:error, _} -> nil
      end
    end
  end

  defp version_check(config) do
    time = DateTime.utc_now() |> DateTime.to_unix()

    case last_version_check(config) do
      {:ok, timestamp} when time - 12 * 60 * 60 <= timestamp -> nil
      _ -> maybe_prompt_update(time, config)
    end
  end

  @doc false
  # A missing, unreadable, or corrupt cache file just means "we don't know when we
  # last checked". It must never abort the scan.
  def last_version_check(config) do
    case :file.open(config, [:read]) do
      {:ok, iofile} ->
        line = :file.read_line(iofile)
        :file.close(iofile)
        parse_version_check(line)

      {:error, _} ->
        :error
    end
  end

  defp parse_version_check({:ok, ~c"sobelow-" ++ timestamp}) do
    case Integer.parse(to_string(timestamp)) do
      {timestamp, _} -> {:ok, timestamp}
      :error -> :error
    end
  end

  defp parse_version_check(_), do: :error

  defp get_sobelow_version do
    {:ok, _} = Application.ensure_all_started(:ssl)

    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = :inets.start(:httpc, [{:profile, :sobelow}])

    url = ~c"https://sobelow.io/version"

    http_options = [
      ssl: [
        verify: :verify_none
        # We cannot use exclusively use OTP 25+ yet, but when we can - uncomment the following few lines
        # verify: :verify_peer,
        # cacertfile: :public_key.cacerts_get()
      ],
      timeout: 10_000
    ]

    IO.puts(:stderr, "Checking Sobelow version...\n")

    case :httpc.request(:get, {url, []}, http_options, []) do
      {:ok, {{_, 200, _}, _, vsn}} ->
        Version.parse!(String.trim(to_string(vsn)))

      _ ->
        MixIO.error("Error fetching version number.\n")
        @v
    end
  after
    :inets.stop(:httpc, :sobelow)
  end

  defp maybe_prompt_update(time, cfile) do
    installed_vsn = Version.parse!(@v)

    cmp =
      get_sobelow_version()
      |> Version.compare(installed_vsn)

    case cmp do
      :gt ->
        MixIO.error("""
        A new version of Sobelow is available:
        mix archive.install hex sobelow
        """)

      _ ->
        nil
    end

    timestamp = "sobelow-" <> to_string(time)

    case :file.open(cfile, [:write, :read]) do
      {:ok, iofile} ->
        :ok = :file.pwrite(iofile, 0, timestamp)
        :ok = :file.close(iofile)

      _ ->
        File.write(cfile, timestamp)
    end
  end

  def get_mod(mod_string) do
    case mod_string do
      "XSS" -> Sobelow.XSS
      "XSS.Raw" -> Sobelow.XSS.Raw
      "XSS.SendResp" -> Sobelow.XSS.SendResp
      "XSS.ContentType" -> Sobelow.XSS.ContentType
      "XSS.HTML" -> Sobelow.XSS.HTML
      "SQL" -> Sobelow.SQL
      "SQL.Query" -> Sobelow.SQL.Query
      "SQL.Stream" -> Sobelow.SQL.Stream
      "Misc" -> Sobelow.Misc
      "Misc.BinToTerm" -> Sobelow.Misc.BinToTerm
      "Misc.FilePath" -> Sobelow.Misc.FilePath
      "RCE" -> Sobelow.RCE
      "RCE.EEx" -> Sobelow.RCE.EEx
      "RCE.CodeModule" -> Sobelow.RCE.CodeModule
      "Config" -> Sobelow.Config
      "Config.CSRF" -> Sobelow.Config.CSRF
      "Config.CSRFRoute" -> Sobelow.Config.CSRFRoute
      "Config.Headers" -> Sobelow.Config.Headers
      "Config.CSP" -> Sobelow.Config.CSP
      "Config.Secrets" -> Sobelow.Config.Secrets
      "Config.HTTPS" -> Sobelow.Config.HTTPS
      "Config.HSTS" -> Sobelow.Config.HSTS
      "Config.CSWH" -> Sobelow.Config.CSWH
      "Vuln" -> Sobelow.Vuln
      "Vuln.CookieRCE" -> Sobelow.Vuln.CookieRCE
      "Vuln.HeaderInject" -> Sobelow.Vuln.HeaderInject
      "Vuln.PlugNull" -> Sobelow.Vuln.PlugNull
      "Vuln.Redirect" -> Sobelow.Vuln.Redirect
      "Vuln.Coherence" -> Sobelow.Vuln.Coherence
      "Vuln.Ecto" -> Sobelow.Vuln.Ecto
      "Traversal" -> Sobelow.Traversal
      "Traversal.SendFile" -> Sobelow.Traversal.SendFile
      "Traversal.FileModule" -> Sobelow.Traversal.FileModule
      "Traversal.SendDownload" -> Sobelow.Traversal.SendDownload
      "CI" -> Sobelow.CI
      "CI.System" -> Sobelow.CI.System
      "CI.OS" -> Sobelow.CI.OS
      "DOS" -> Sobelow.DOS
      "DOS.StringToAtom" -> Sobelow.DOS.StringToAtom
      "DOS.ListToAtom" -> Sobelow.DOS.ListToAtom
      "DOS.BinToAtom" -> Sobelow.DOS.BinToAtom
      _ -> nil
    end
  end

  def get_ignored do
    get_env(:ignored)
    |> Enum.map(&get_mod/1)
  end

  def vuln?({vars, _, _}) do
    if Enum.empty?(vars) do
      false
    else
      true
    end
  end

  defp ignored_file?(filename, ignored_files) do
    Enum.any?(ignored_files, fn ignored_file ->
      String.ends_with?(ignored_file, filename)
    end)
  end

  def version do
    @v
    |> IO.puts()
  end
end
