defmodule Sobelow.SafeWrite do
  @moduledoc false
  import Bitwise, only: [band: 2]

  # An atomic directory claim also coordinates independent CLI VMs. Fail rather
  # than steal a lock: after an uncatchable interruption an orphan must be
  # removed by the operator once no writer is running.
  def transaction!(path, fun) do
    lock = path <> ".sobelow-lock"

    case File.mkdir(lock) do
      :ok ->
        try do
          fun.()
        after
          File.rmdir(lock)
        end

      {:error, :eexist} ->
        raise Sobelow.ScanError,
              "#{path} is locked; retry when the writer finishes (lock: #{lock})."

      {:error, reason} ->
        raise Sobelow.ScanError, "Could not lock #{path}: #{:file.format_error(reason)}"
    end
  end

  def write(path, contents) do
    with {:ok, target, mode} <- target(path, 0) do
      suffix = :crypto.strong_rand_bytes(12) |> Base.encode16(case: :lower)
      temporary = target <> ".sobelow-#{suffix}.tmp"

      with {:ok, file} <- :file.open(temporary, [:write, :binary, :exclusive]) do
        try do
          result = persist(file, contents)

          with :ok <- result,
               :ok <- permissions(temporary, mode),
               do: File.rename(temporary, target)
        after
          File.rm(temporary)
        end
      end
    end
  end

  defp persist(file, contents) do
    result = with :ok <- :file.write(file, contents), do: :file.sync(file)
    close = :file.close(file)
    with :ok <- result, do: close
  end

  def write!(path, contents) do
    case write(path, contents) do
      :ok ->
        :ok

      {:error, reason} ->
        raise Sobelow.ScanError, "Could not write #{path}: #{:file.format_error(reason)}"
    end
  end

  defp target(_path, depth) when depth > 40, do: {:error, :eloop}

  defp target(path, depth) do
    case File.lstat(path) do
      {:ok, %{type: :symlink}} ->
        with {:ok, linked} <- File.read_link(path) do
          # Leave dot segments for the OS; a directory symlink followed by
          # `..` is not equivalent to lexical normalization.
          linked =
            if Path.type(linked) == :relative,
              do: Path.join(Path.dirname(path), linked),
              else: linked

          target(linked, depth + 1)
        end

      {:ok, %{type: :directory}} ->
        {:error, :eisdir}

      {:ok, %{type: :regular, access: access, mode: mode}} when access in [:write, :read_write] ->
        {:ok, path, band(mode, 0o777)}

      {:ok, %{type: :regular}} ->
        {:error, :eacces}

      {:ok, _} ->
        {:error, :einval}

      {:error, :enoent} ->
        {:ok, path, nil}

      error ->
        error
    end
  end

  defp permissions(_path, nil), do: :ok
  defp permissions(path, mode), do: File.chmod(path, mode)
end
