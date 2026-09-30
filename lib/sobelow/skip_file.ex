defmodule Sobelow.SkipFile do
  @moduledoc false
  @skips ".sobelow-skips"

  alias Sobelow.Finding
  alias Sobelow.FindingLog
  alias Sobelow.Fingerprint

  def clear(project_root) do
    cfile = project_root <> @skips

    if File.exists?(cfile) do
      File.rm!(cfile)
    end
  end

  def load(project_root) do
    cfile = project_root <> @skips

    if File.exists?(cfile) do
      case :file.open(cfile, [:read]) do
        {:ok, iofile} ->
          :file.read_line(iofile) |> load_ignored_fingerprints(iofile)
          :file.close(iofile)

        {:error, _} ->
          nil
      end
    end
  end

  def mark_all(project_root) do
    cfile = project_root <> @skips

    case Fingerprint.new_skips() do
      [] ->
        nil

      new_fingerprints ->
        findings =
          FindingLog.log()
          |> Map.values()
          |> List.flatten()
          |> Map.new(fn {_details, finding, _} -> {finding.fingerprint, finding} end)

        skip_entries = Enum.map(new_fingerprints, &skip_entry(&1, Map.get(findings, &1)))
        write_skips(cfile, skip_entries)
    end
  end

  defp skip_entry(fingerprint, %Finding{} = finding) do
    filename = Sobelow.Scan.relative_filename(finding.filename)
    "#{finding.type},#{filename}:#{finding.vuln_line_no},#{fingerprint}"
  end

  defp skip_entry(fingerprint, nil), do: fingerprint

  defp write_skips(cfile, entries) do
    if Sobelow.get_env(:legacy_skips) do
      append_skips(cfile, entries)
    else
      rewrite_skips(cfile, entries)
    end
  end

  # `--legacy-skips` preserves the historical append-only behaviour.
  defp append_skips(cfile, entries) do
    result =
      with {:ok, iofile} <- :file.open(cfile, [:append]) do
        try do
          :file.write(iofile, ["\n", entries |> sort_skips() |> Enum.join("\n")])
        after
          :file.close(iofile)
        end
      end

    case result do
      :ok ->
        :ok

      {:error, reason} ->
        raise Sobelow.ScanError, "Could not append #{cfile}: #{:file.format_error(reason)}"
    end
  end

  # Merge before sorting so repeated scans keep the entire file ordered.
  defp rewrite_skips(cfile, entries) do
    existing =
      case File.read(cfile) do
        {:ok, contents} ->
          contents |> String.split("\n") |> Enum.map(&String.trim/1)

        {:error, :enoent} ->
          []

        {:error, reason} ->
          raise Sobelow.ScanError, "Could not read #{cfile}: #{:file.format_error(reason)}"
      end

    lines =
      (existing ++ entries)
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()
      |> sort_skips()

    Sobelow.SafeWrite.write!(cfile, Enum.join(lines, "\n") <> "\n")
  end

  defp sort_skips(entries), do: Enum.sort_by(entries, &skip_sort_key/1)

  # Order locations numerically (line 2 before line 10). Preserve comments at
  # the top, old bare fingerprints afterward, and unknown entries at the end.
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

  defp load_ignored_fingerprints({:ok, line}, iofile) do
    line_str = to_string(line) |> String.trim()

    # Accept both bare hashes and type,filename:line,hash entries.
    fingerprint =
      case String.split(line_str, ",") do
        [fingerprint] when fingerprint != "" ->
          fingerprint

        [_type, _filename_line_n, fingerprint] when fingerprint != "" ->
          fingerprint

        _ ->
          nil
      end

    if fingerprint, do: Fingerprint.put_ignore(fingerprint)
    :file.read_line(iofile) |> load_ignored_fingerprints(iofile)
  end

  defp load_ignored_fingerprints(:eof, _), do: nil
  defp load_ignored_fingerprints(_, _), do: nil
end
