defmodule Sobelow do
  @moduledoc """
  Sobelow is a static analysis tool for discovering
  vulnerabilities in Phoenix applications.
  """
  @v Mix.Project.config()[:version]
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

  alias Sobelow.Finding
  alias Sobelow.FindingLog
  alias Sobelow.Fingerprint
  alias Sobelow.IO, as: MixIO
  alias Sobelow.Utils

  def run do
    Sobelow.Scanner.run(@submodules, @v)
  end

  @doc false
  def exit_status(exit_on, %{high: high, medium: medium, low: low}) do
    case exit_on do
      :high -> if high > 0, do: 1
      :medium -> if high + medium > 0, do: 1
      :low -> if high + medium + low > 0, do: 1
      _ -> 0
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
    skipped? =
      get_env(:skip) &&
        ((finding.legacy_fingerprint &&
            Sobelow.Scan.ignored_fingerprint?(finding.legacy_fingerprint)) ||
           (finding.fingerprint && Sobelow.Scan.ignored_fingerprint?(finding.fingerprint)))

    !skipped? && meets_threshold?(severity)
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
      only: get_env(:only) || [],
      ignore_files: relative_ignored_files(),
      include_mix_tasks: get_env(:include_mix_tasks),
      include_scripts: get_env(:include_scripts),
      out: get_env(:out),
      private: get_env(:private),
      router: get_env(:router),
      skip: get_env(:skip),
      summary: get_env(:summary),
      threshold: get_env(:threshold),
      verbose: get_env(:verbose)
    ]

    yes? =
      if File.exists?(conf_file) do
        MixIO.yes?("The file .sobelow-conf already exists. Are you sure you want to overwrite?")
      else
        true
      end

    if yes? do
      Sobelow.SafeWrite.write!(
        conf_file,
        inspect(conf, limit: :infinity, printable_limit: :infinity)
      )

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

  def get_env(key), do: Sobelow.Scan.env(key)

  @doc false
  defdelegate version_check_file(), to: Sobelow.VersionCheck

  @doc false
  defdelegate last_version_check(config), to: Sobelow.VersionCheck

  @doc false
  defdelegate parse_remote_version(body), to: Sobelow.VersionCheck

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
      # Keep the old rule name accepted for ignores and skips.
      "Vuln.Plug" -> Sobelow.Vuln.CookieRCE
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
    Sobelow.Scan.ignored(&ignored_modules/0)
  end

  @doc false
  # Every module a scan should skip. `--only` is applied by ignoring whatever it
  # does not select, so categories and checks keep a single filtering path.
  def ignored_modules do
    ignored = Enum.map(get_env(:ignored) || [], &get_mod/1)

    case get_env(:only) || [] do
      [] -> ignored
      only -> ignored ++ (all_modules() -- selected_modules(only))
    end
  end

  defp all_modules do
    @submodules ++ finding_modules()
  end

  # A category selects all of its checks; a check also keeps its category, which
  # would otherwise be dropped before its checks run.
  defp selected_modules(only) do
    Enum.flat_map(only, fn name ->
      mod = get_mod(name)

      case Enum.find(@submodules, &(&1 == mod or mod in &1.finding_modules())) do
        nil -> []
        ^mod -> [mod | apply(mod, :finding_modules, [])]
        category -> [category, mod]
      end
    end)
  end

  @doc false
  def allowed_checks(category, submodules, skips \\ []) do
    Sobelow.Scan.allowed_checks(category, fn -> submodules -- get_ignored() end) -- skips
  end

  def vuln?({vars, _, _}) do
    not Enum.empty?(vars)
  end

  def version do
    IO.puts(@v)
  end
end
