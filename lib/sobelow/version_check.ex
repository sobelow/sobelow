defmodule Sobelow.VersionCheck do
  @moduledoc false
  @home "~/.sobelow"
  @vsncheck "sobelow-vsn-check"

  # Keep auxiliary I/O separate from scan orchestration. The fetch boundary can
  # be exercised without contacting the version service or weakening TLS.
  def run(cache, installed, fetch_version \\ &fetch_latest/1) do
    case File.mkdir_p(Path.dirname(cache)) do
      :ok -> refresh(cache, installed, fetch_version)
      {:error, _} -> nil
    end
  rescue
    _ -> nil
  catch
    :exit, _ -> nil
  end

  defp refresh(cache, installed, fetch_version) do
    case last_version_check(cache) do
      {:ok, timestamp} ->
        unless fresh?(timestamp), do: refresh_locked(cache, installed, fetch_version)

      :error ->
        refresh_locked(cache, installed, fetch_version)
    end
  end

  defp fresh?(timestamp) do
    age = System.system_time(:second) - timestamp
    age >= 0 and age <= 12 * 60 * 60
  end

  defp refresh_locked(cache, installed, fetch_version) do
    Sobelow.SafeWrite.transaction!(cache, fn ->
      case last_version_check(cache) do
        {:ok, timestamp} ->
          unless fresh?(timestamp), do: update(cache, installed, fetch_version)

        :error ->
          update(cache, installed, fetch_version)
      end
    end)
  end

  defp update(cache, installed, fetch_version) do
    case fetch_version.(installed) do
      %Version{} = version ->
        if Version.compare(version, Version.parse!(installed)) == :gt do
          Sobelow.IO.error("""
          A new version of Sobelow is available:
          mix archive.install hex sobelow
          """)
        end

        Sobelow.SafeWrite.write(cache, "sobelow-#{System.system_time(:second)}")

      :error ->
        nil
    end
  end

  def fetch(installed, request \\ &:httpc.request/4, certificates \\ &trusted_cacerts/0) do
    case fetch_latest(installed, request, certificates) do
      :error -> Version.parse!(installed)
      version -> version
    end
  end

  defp fetch_latest(installed), do: fetch_latest(installed, &:httpc.request/4, &trusted_cacerts/0)

  defp fetch_latest(_installed, request, certificates) do
    case certificates.() do
      {:ok, certs} ->
        {:ok, _} = Application.ensure_all_started(:ssl)
        {:ok, _} = Application.ensure_all_started(:inets)

        http_options = [
          ssl: [
            verify: :verify_peer,
            cacerts: certs,
            customize_hostname_check: [
              match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
            ]
          ],
          timeout: 10_000
        ]

        IO.puts(:stderr, "Checking Sobelow version...\n")

        case request.(:get, {~c"https://sobelow.io/version", []}, http_options, []) do
          {:ok, {{_, 200, _}, _, body}} ->
            case parse_remote_version(body) do
              {:ok, version} -> version
              :error -> :error
            end

          _ ->
            :error
        end

      :error ->
        :error
    end
  end

  def trusted_cacerts(provider \\ :public_key) do
    if Code.ensure_loaded?(provider) and function_exported?(provider, :cacerts_get, 0) do
      case apply(provider, :cacerts_get, []) do
        [_ | _] = certs -> {:ok, certs}
        _ -> :error
      end
    else
      :error
    end
  end

  @doc false
  # `SOBELOW_HOME` overrides the *directory* the version-check timestamp is cached in.
  def version_check_file do
    (System.get_env("SOBELOW_HOME") || @home)
    |> Path.expand()
    |> Path.join(@vsncheck)
  end

  @doc false
  # A missing, unreadable, or corrupt cache file just means "we don't know when we
  # last checked". It must never abort the scan.
  def last_version_check(config) do
    case File.read(config) do
      {:ok, contents} -> parse_version_check(String.trim_trailing(contents, "\n"))
      {:error, _} -> :error
    end
  end

  defp parse_version_check("sobelow-" <> timestamp) do
    case Integer.parse(timestamp) do
      {timestamp, ""} when timestamp >= 0 -> {:ok, timestamp}
      _ -> :error
    end
  end

  defp parse_version_check(_), do: :error

  @doc false
  def parse_remote_version(body) when is_binary(body) or is_list(body) do
    body |> to_string() |> String.trim() |> Version.parse()
  end

  def parse_remote_version(_), do: :error
end
