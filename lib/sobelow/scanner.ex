defmodule Sobelow.Scanner do
  @moduledoc false

  alias Sobelow.Config
  alias Sobelow.FindingLog
  alias Sobelow.Fingerprint
  alias Sobelow.MetaLog
  alias Sobelow.Scan
  alias Sobelow.Scan.Discovery
  alias Sobelow.SkipFile
  alias Sobelow.Vuln

  def run(categories, version) do
    Scan.with_scan(fn -> do_run(categories, version) end)
  end

  defp do_run(categories, version) do
    project_root = Sobelow.get_env(:root) <> "/"
    version_check(version)
    project = Discovery.prepare(project_root, categories)
    allowed = project.allowed
    init_state(project_root, project.templates)

    if Sobelow.get_env(:clear_skip) do
      SkipFile.clear(project_root)
      System.halt(0)
    end

    if Sobelow.format() not in ["quiet", "compact", "flycheck", "json"],
      do: IO.puts(:stderr, print_banner(version))

    Application.put_env(:sobelow, :app_name, project.app_name)
    Scan.configure(categories)

    # These are single units of work, run without a task timeout.
    if Config in allowed, do: Config.fetch(project_root, project.routers, project.endpoints)
    if Vuln in allowed, do: Vuln.get_vulns(project_root)
    allowed = allowed -- [Config, Vuln]

    scan_workers(project.files, fn meta_file ->
      Enum.each(meta_file.scan_contexts, fn context ->
        context_meta =
          Map.merge(
            Map.take(meta_file, [:filename, :file_path]),
            Map.drop(context, [:functions])
          )

        Enum.each(context.functions, fn {fun, lexical} ->
          get_fun_vulns(fun, Map.put(context_meta, :lexical, lexical), project_root, allowed)
        end)
      end)
    end)

    if Sobelow.XSS in allowed do
      scan_workers(project.templates, fn {_, meta_file} ->
        Sobelow.XSS.get_template_vulns(meta_file)
      end)
    end

    Scan.print_summary(Sobelow.get_env(:summary))

    if Sobelow.format() != "txt" do
      print_output(version)
    else
      FindingLog.print_txt()
      IO.puts(:stderr, "... SCAN COMPLETE ...\n")
    end

    if Sobelow.get_env(:mark_skip_all), do: SkipFile.mark_all(project_root)
    exit_with_status()
  end

  # Source and template phases share the same worker lifecycle. Keep batching
  # and scan-local options attached until each worker has finished its checks.
  defp scan_workers(values, fun) do
    scan = Scan.current()

    values
    |> Task.async_stream(
      fn value ->
        Scan.attach(scan, fn ->
          FindingLog.with_batch(fn -> Fingerprint.with_batch(fn -> fun.(value) end) end)
        end)
      end,
      timeout: :infinity
    )
    |> Stream.run()
  end

  defp init_state(project_root, template_meta_files) do
    Enum.each([FindingLog, MetaLog, Fingerprint], &start_fresh_state/1)
    SkipFile.load(project_root)
    MetaLog.add_templates(template_meta_files)
  end

  defp start_fresh_state(module) do
    if pid = Process.whereis(module), do: GenServer.stop(pid, :normal)
    {:ok, _pid} = module.start_link()
  end

  defp print_output(version) do
    details =
      case Sobelow.output_format() do
        "json" ->
          FindingLog.json(version)

        "quiet" ->
          FindingLog.quiet()

        "sarif" ->
          FindingLog.sarif(version)

        _ ->
          nil
      end

    if !is_nil(details) do
      print_std_or_file(details)
    end
  end

  defp print_std_or_file(details) do
    case Sobelow.get_env(:out) do
      nil ->
        IO.puts(details)

      "" ->
        IO.puts(details)

      out ->
        case File.write(out, details) do
          :ok ->
            :ok

          {:error, reason} ->
            raise Sobelow.ScanError, "Could not write #{out}: #{:file.format_error(reason)}"
        end
    end
  end

  defp exit_with_status do
    exit_on = Sobelow.get_env(:exit_on)
    status = Sobelow.exit_status(exit_on, FindingLog.counts())

    if exit_on && !is_nil(status) do
      System.halt(status)
    end
  end

  defp print_banner(version) do
    """
    ##############################################
    #                                            #
    #          Running Sobelow - v#{version}         #
    #  Created by Griffin Byatt - @griffinbyatt  #
    #     NCC Group - https://nccgroup.trust     #
    #                                            #
    ##############################################
    """
  end

  defp get_fun_vulns({fun, skips}, meta_file, web_root, mods) do
    skip_mods =
      skips
      |> Enum.map(&Sobelow.get_mod/1)

    Sobelow.Lexical.with_context(meta_file.lexical, fn ->
      Sobelow.FunctionAnalysis.with_fun(fun, fn ->
        Enum.each(mods -- skip_mods, fn mod ->
          params = [fun, meta_file, web_root, skip_mods]
          apply(mod, :get_vulns, params)
        end)
      end)
    end)
  end

  defp get_fun_vulns(fun, meta_file, web_root, mods) do
    get_fun_vulns({fun, []}, meta_file, web_root, mods)
  end

  defp version_check(version) do
    unless Sobelow.get_env(:private),
      do: Sobelow.VersionCheck.run(Sobelow.version_check_file(), version)
  rescue
    _ -> nil
  catch
    :exit, _ -> nil
  end
end
