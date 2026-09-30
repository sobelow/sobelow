defmodule Sobelow.VersionCheckTest do
  use Sobelow.CoverageCase, async: false
  alias Sobelow.VersionCheck

  defmodule Certificates do
    def cacerts_get, do: [:certificate]
  end

  defmodule EmptyCertificates do
    def cacerts_get, do: []
  end

  @tag :tmp_dir
  test "a recent timestamp avoids network access", %{tmp_dir: dir} do
    cache = Path.join(dir, "last_version_check")
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    File.write!(cache, "sobelow-#{timestamp}")

    assert VersionCheck.run(cache, "0.15.0", fn _ -> flunk("unexpected version request") end) ==
             nil
  end

  @tag :tmp_dir
  test "missing and corrupt caches refresh and only newer releases produce a notice", %{
    tmp_dir: dir
  } do
    cache = Path.join([dir, "new", "last_version_check"])

    output =
      capture_io(:stderr, fn ->
        VersionCheck.run(cache, "0.15.0", fn _ -> Version.parse!("0.16.0") end)
      end)

    assert output =~ "new version of Sobelow"
    assert {:ok, _} = Sobelow.last_version_check(cache)

    File.write!(cache, "corrupt")

    assert capture_io(:stderr, fn ->
             VersionCheck.run(cache, "0.15.0", fn _ -> Version.parse!("0.15.0") end)
           end) == ""

    assert {:ok, _} = Sobelow.last_version_check(cache)
  end

  @tag :tmp_dir
  test "filesystem and fetch failures never prevent analysis", %{tmp_dir: dir} do
    parent = Path.join(dir, "regular")
    File.write!(parent, "contents")

    assert VersionCheck.run(Path.join(parent, "cache"), "0.15.0", fn _ ->
             flunk("unexpected request")
           end) == nil

    cache = Path.join(dir, "cache")
    assert VersionCheck.run(cache, "0.15.0", fn _ -> raise "network failure" end) == nil
    assert VersionCheck.run(cache, "0.15.0", fn _ -> exit(:network_failure) end) == nil

    assert VersionCheck.run(dir, "0.15.0", fn _ -> Version.parse!("0.15.0") end) ==
             {:error, :eisdir}

    assert File.read!(parent) == "contents"
  end

  test "requests require trusted certificates and verify peer and hostname" do
    request = fn :get, {url, []}, options, [] ->
      assert url == ~c"https://sobelow.io/version"
      assert options[:timeout] == 10_000
      assert options[:ssl][:verify] == :verify_peer
      assert options[:ssl][:cacerts] == [:certificate]
      assert is_function(options[:ssl][:customize_hostname_check][:match_fun], 2)
      {:ok, {{~c"HTTP/1.1", 200, ~c"OK"}, [], "0.16.0\n"}}
    end

    capture_io(:stderr, fn ->
      assert VersionCheck.fetch("0.15.0", request, fn -> {:ok, [:certificate]} end) ==
               Version.parse!("0.16.0")
    end)

    assert VersionCheck.fetch("0.15.0", fn _, _, _, _ -> flunk("untrusted request") end, fn ->
             :error
           end) == Version.parse!("0.15.0")
  end

  test "malformed responses and transport failures retain the installed version" do
    for response <- [
          {:error, :timeout},
          {:ok, {{~c"HTTP/1.1", 500, ~c"Error"}, [], "0.16.0"}},
          {:ok, {{~c"HTTP/1.1", 200, ~c"OK"}, [], "invalid"}}
        ] do
      capture_io(:stderr, fn ->
        assert VersionCheck.fetch("0.15.0", fn _, _, _, _ -> response end, fn ->
                 {:ok, [:certificate]}
               end) == Version.parse!("0.15.0")
      end)
    end

    assert Sobelow.parse_remote_version(nil) == :error
  end

  test "certificate discovery supports absent and empty stores" do
    assert VersionCheck.trusted_cacerts(Certificates) == {:ok, [:certificate]}
    assert VersionCheck.trusted_cacerts(EmptyCertificates) == :error
    assert VersionCheck.trusted_cacerts(__MODULE__) == :error
  end
end
