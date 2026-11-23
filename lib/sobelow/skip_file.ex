defmodule Sobelow.SkipFile do
  @moduledoc false
  @skips ".sobelow-skips"

  alias Sobelow.Finding
  alias Sobelow.FindingLog
  alias Sobelow.Fingerprint

  def clear(project_root) do
    cfile = project_root <> @skips

    Sobelow.SafeWrite.transaction!(cfile, fn ->
      case File.rm(cfile) do
        :ok ->
          :ok

        {:error, :enoent} ->
          :ok

        {:error, reason} ->
          raise Sobelow.ScanError, "Could not clear #{cfile}: #{:file.format_error(reason)}"
      end
    end)
  end

  def load(project_root) do
    cfile = project_root <> @skips

    case read_skips(cfile) do
      {:ok, lines} ->
        Enum.each(lines, fn line ->
          if fingerprint = entry_fingerprint(line), do: Fingerprint.put_ignore(fingerprint)
        end)

      {:error, reason} ->
        IO.puts(:stderr, read_error(cfile, reason) <> "; continuing without saved skips.")
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

    if String.contains?(filename, [",", "\n", "\r"]) do
      fingerprint
    else
      "#{finding.type},#{filename}:#{finding.vuln_line_no},#{fingerprint}"
    end
  end

  defp skip_entry(fingerprint, nil), do: fingerprint

  defp write_skips(cfile, entries) do
    Sobelow.SafeWrite.transaction!(cfile, fn ->
      existing =
        case read_skips(cfile) do
          {:ok, lines} -> lines
          {:error, reason} -> raise Sobelow.ScanError, read_error(cfile, reason)
        end

      known = MapSet.new(existing, &entry_fingerprint/1)
      entries = Enum.reject(entries, &MapSet.member?(known, entry_fingerprint(&1)))

      cond do
        entries == [] -> :ok
        Sobelow.get_env(:legacy_skips) -> append_skips(cfile, entries)
        true -> rewrite_skips(cfile, existing, entries)
      end
    end)
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

  defp read_skips(cfile) do
    case File.read(cfile) do
      {:ok, contents} ->
        {:ok, contents |> String.split("\n") |> Enum.map(&String.trim/1)}

      {:error, :enoent} ->
        {:ok, []}

      error ->
        error
    end
  end

  defp read_error(path, reason), do: "Could not read #{path}: #{:file.format_error(reason)}"

  # Merge before sorting so repeated scans keep the entire file ordered.
  defp rewrite_skips(cfile, existing, entries) do
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

  defp entry_fingerprint("#" <> _), do: nil

  defp entry_fingerprint(line) do
    case String.split(line, ",") do
      [fingerprint] when fingerprint != "" -> fingerprint
      [_type, _location, fingerprint] when fingerprint != "" -> fingerprint
      _ -> nil
    end
  end
end
