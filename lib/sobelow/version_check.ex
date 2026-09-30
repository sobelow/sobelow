defmodule Sobelow.VersionCheck do
  @moduledoc false

  # Keep auxiliary I/O separate from scan orchestration. The fetch boundary can
  # be exercised without contacting the version service or weakening TLS.
  def run(cache, installed, fetch_version \\ &fetch/1) do
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
    time = DateTime.utc_now() |> DateTime.to_unix()

    case Sobelow.last_version_check(cache) do
      {:ok, timestamp} when time - 12 * 60 * 60 <= timestamp -> nil
      _ -> update(time, cache, installed, fetch_version)
    end
  end

  defp update(time, cache, installed, fetch_version) do
    if Version.compare(fetch_version.(installed), Version.parse!(installed)) == :gt do
      Sobelow.IO.error("""
      A new version of Sobelow is available:
      mix archive.install hex sobelow
      """)
    end

    timestamp = "sobelow-" <> to_string(time)

    case :file.open(cache, [:write, :read]) do
      {:ok, iofile} ->
        :ok = :file.pwrite(iofile, 0, timestamp)
        :ok = :file.close(iofile)

      _ ->
        File.write(cache, timestamp)
    end
  end

  def fetch(installed, request \\ &:httpc.request/4, certificates \\ &trusted_cacerts/0) do
    case certificates.() do
      {:ok, certs} ->
        {:ok, _} = Application.ensure_all_started(:ssl)
        {:ok, _} = Application.ensure_all_started(:inets)
        {:ok, _} = :inets.start(:httpc, [{:profile, :sobelow}])

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
            case Sobelow.parse_remote_version(body) do
              {:ok, version} -> version
              :error -> Version.parse!(installed)
            end

          _ ->
            Version.parse!(installed)
        end

      :error ->
        Version.parse!(installed)
    end
  after
    :inets.stop(:httpc, :sobelow)
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
end
