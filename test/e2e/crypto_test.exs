defmodule SobelowTest.E2E.CryptoTest do
  use Sobelow.ScanCase, async: false

  setup do
    temp_fixture_file("basic", "lib/basic_web/controllers/crypto_controller.ex", """
    defmodule BasicWeb.CryptoController do
      use BasicWeb, :controller
      def index(conn, params) do
        :crypto.hash(:md5, "literal")
        :crypto.hash(:sha256, params["password"])
        :crypto.mac(:hmac, :md5, "key", "data")
        :crypto.crypto_one_time(:aes_128_ecb, key, data, true)
        :crypto.crypto_one_time(:aes_128_cbc, key, iv, data, true)
        conn
      end
      # sobelow_skip ["Crypto"]
      def skipped(data), do: :erlang.md5(data)
    end
    """)

    temp_fixture_file("basic", "lib/crypto_helper.ex", """
    defmodule CryptoHelper do
      def checksum(data), do: :crypto.hash(:md5, data)
    end
    """)

    :ok
  end

  test "registers all rules with stable IDs and confidence independent of taint" do
    report = scan("basic", skip: true)
    hashes = findings_for(report, "Crypto.WeakHash")
    assert Enum.frequencies_by(hashes, & &1["confidence"]) == %{"medium" => 1, "low" => 2}

    assert Enum.frequencies_by(findings_for(report, "Crypto.WeakCipher"), & &1["confidence"]) ==
             %{"high" => 1, "low" => 1}

    assert Sobelow.get_mod("Crypto") == Sobelow.Crypto

    assert Enum.map(Sobelow.Crypto.finding_modules(), & &1.id()) ==
             ["SBLW038", "SBLW039", "SBLW044"]

    ids = Enum.map(Sobelow.finding_modules(), & &1.id())
    assert length(ids) == length(Enum.uniq(ids))
  end

  test "supports ignores, skips, thresholds and all renderers" do
    assert [] = scan("basic", ignored: ["Crypto"]) |> findings_for("Crypto.WeakHash")
    assert [] = scan("basic", ignored: ["Crypto.WeakCipher"]) |> findings_for("Crypto.WeakCipher")
    assert length(scan("basic") |> findings_for("Crypto.WeakHash")) == 4
    assert length(scan("basic", skip: true) |> findings_for("Crypto.WeakHash")) == 3
    assert [] = scan("basic", threshold: :high) |> findings_for("Crypto.WeakHash")

    for format <- ["txt", "compact", "flycheck", "github"] do
      {output, _} = scan_io("basic", format: format)
      assert output =~ "Crypto.WeakCipher"
    end

    {output, _} = scan_io("basic", format: "sarif", skip: true)
    [run] = Jason.decode!(output)["runs"]

    for id <- ["SBLW038", "SBLW039"] do
      assert Enum.any?(run["results"], &(&1["ruleId"] == id))
      assert Enum.any?(run["tool"]["driver"]["rules"], &(&1["id"] == id))
    end
  end

  test "reports streaming Erlang MD5 once at the initializer" do
    temp_fixture_file("basic", "lib/md5_stream.ex", """
    defmodule MD5Stream do
      import :erlang, only: [md5_init: 0]
      def digest(data) do
        context = :erlang.md5_init()
        context = :erlang.md5_update(context, data)
        :erlang.md5_final(context)
      end
      def imported(), do: md5_init()
      def captured(), do: &:erlang.md5_init/0
      def imported_capture(), do: &md5_init/0
    end
    """)

    found = scan("basic", only: ["Crypto.WeakHash"]) |> findings_for("Crypto.WeakHash")
    stream = Enum.filter(found, &String.ends_with?(&1["file"], "md5_stream.ex"))
    assert Enum.sort(Enum.map(stream, & &1["line"])) == [4, 8, 9, 10]
    assert Enum.all?(stream, &(&1["confidence"] == "low"))
  end
end
