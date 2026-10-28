defmodule SobelowTest.E2E.ErlangCallArgumentsTest do
  use Sobelow.ScanCase, async: false

  test "file checks resolve imported calls, pipes and captures" do
    temp_fixture_file("basic", "lib/file_imports.ex", """
    defmodule FileImports do
      import :file, only: [consult: 1, script: 1, path_script: 2]
      def terms(file), do: consult(file)
      def code(file), do: script(file)
      def pipe(paths, file), do: paths |> path_script(file)
      def capture(files), do: Enum.map(files, &script/1)
      def inline(files), do: Enum.map(files, &script(&1))
      def qualified(file), do: :file.script(file)
    end
    """)

    report = scan("basic", only: ["DOS.Consult", "RCE.File"])
    assert lines(report, "DOS.Consult") == [3]
    assert lines(report, "RCE.File") == [4, 5, 6, 7, 8]
  end

  test "crypto checks resolve imported calls with effective pipe arities" do
    temp_fixture_file("basic", "lib/crypto_imports.ex", """
    defmodule CryptoImports do
      import :crypto, only: [hash: 2, crypto_one_time: 4]
      import :erlang, only: [md5: 1]
      def digest(data), do: hash(:md5, data)
      def pipe(data), do: :md5 |> hash(data)
      def inline(data), do: Enum.map(data, &hash(:sha, &1))
      def capture(data), do: Enum.map(data, &md5/1)
      def cipher(data, key), do: crypto_one_time(:rc4, key, data, true)
      def cipher_pipe(data, key), do: :rc4 |> crypto_one_time(key, data, true)
      def qualified(data), do: :crypto.hash(:md5, data)
    end
    """)

    report = scan("basic", only: ["Crypto"])
    assert lines(report, "Crypto.WeakHash") == [4, 5, 6, 7, 10]
    assert lines(report, "Crypto.WeakCipher") == [8, 9]
  end

  test "unrelated imports, excluded arities and neighboring modules stay unreported" do
    temp_fixture_file("basic", "lib/unrelated_imports.ex", """
    defmodule UnrelatedImports do
      import Other, only: [hash: 2, script: 1]
      def digest(data), do: hash(:md5, data)
      def code(file), do: script(file)
      def excluded(data) do
        import :crypto, except: [hash: 2]
        :md5 |> hash(data)
      end
      def wrong_arity(file) do
        import :file, only: [script: 1]
        file |> script([])
      end
      def excluded_capture(files) do
        import :file, except: [script: 1]
        Enum.map(files, &script/1)
      end
    end
    defmodule Neighbor do
      def digest(data), do: hash(:md5, data)
      def code(file), do: script(file)
      defp hash(_algorithm, data), do: data
      defp script(file), do: file
    end
    """)

    report = scan("basic", only: ["DOS.Consult", "RCE.File", "Crypto"])

    for check <- ["DOS.Consult", "RCE.File", "Crypto.WeakHash", "Crypto.WeakCipher"] do
      assert [] = findings_for(report, check)
    end
  end

  defp lines(report, check) do
    report |> findings_for(check) |> Enum.map(& &1["line"]) |> Enum.sort()
  end
end
