defmodule SobelowTest.E2E.SecurityAdversarialTest do
  use Sobelow.ScanCase, async: false

  test "bare imported pipes retain detection, arity ownership and original ASTs" do
    temp_fixture_file("basic", "lib/basic_web/controllers/bare_sources_controller.ex", """
    defmodule BasicWeb.BareSourcesController do
      use BasicWeb, :controller
      import Code, only: [compile_string: 1, require_file: 1]
      import Module, only: [concat: 1]
      def source(input), do: input |> compile_string
      def file(path), do: path |> require_file
      def names(input), do: input |> concat
      def qualified(input), do: input |> Code.compile_string
      def excluded(input) do
        import Code, except: [compile_string: 1]
        input |> compile_string
      end
    end
    defmodule Neighbor do
      def names(input), do: input |> concat
      defp concat(input), do: input
    end
    """)

    report = scan("basic", only: ["RCE.Compile", "DOS.ModuleConcat"])
    assert locations(report, "RCE.Compile") == [{5, "high"}, {6, "medium"}, {8, "high"}]
    assert locations(report, "DOS.ModuleConcat") == [{7, "high"}]

    sources = Sobelow.FindingLog.log().high |> Enum.map(fn {_, f, _} -> f.vuln_source end)
    assert Enum.any?(sources, &match?({:compile_string, _, nil}, &1))
    assert Enum.any?(sources, &match?({:concat, _, nil}, &1))

    {output, _} = scan_io("basic", only: ["RCE.Compile", "DOS.ModuleConcat"], format: "sarif")
    assert length(hd(Jason.decode!(output)["runs"])["results"]) == 4
  end

  test "qualified Kernel word sigils preserve ownership and parameter confidence" do
    temp_fixture_file("basic", "lib/basic_web/controllers/qualified_words_controller.ex", ~S'''
    defmodule BasicWeb.QualifiedWordsController do
      use BasicWeb, :controller
      alias Kernel, as: Words
      def index(conn, %{"word" => word}) do
        Kernel.sigil_w("prefix_#{word}", [?a])
        Elixir.Kernel.sigil_w("prefix_#{word}", [?a])
        Words.sigil_w("prefix_#{word}", [?a])
        Kernel.sigil_w("fixed", [?a])
        Kernel.sigil_w("prefix_#{word}", [])
      end
    end
    defmodule CustomWords do
      alias Other, as: Kernel
      def words(word), do: Kernel.sigil_w("prefix_#{word}", [?a])
    end
    ''')

    report = scan("basic", only: ["DOS.BinToAtom"])
    assert locations(report, "DOS.BinToAtom") == [{5, "high"}, {6, "high"}, {7, "high"}]
    assert Enum.all?(findings_for(report, "DOS.BinToAtom"), &(&1["variable"] == "word"))
  end

  test "constructed quoted ASTs retain controller parameters inside literal containers" do
    temp_fixture_file("basic", "lib/basic_web/controllers/quoted_controller.ex", """
    defmodule BasicWeb.QuotedController do
      use BasicWeb, :controller
      def index(conn, %{"input" => input}) do
        Code.compile_quoted({:__block__, [], [input]})
        Code.compile_quoted({:%{}, [], [{:body, input}]})
        Code.compile_quoted({:literal, [], []})
      end
    end
    """)

    report = scan("basic", only: ["RCE.Compile"], threshold: :high)
    assert locations(report, "RCE.Compile") == [{4, "high"}, {5, "high"}]
    assert Enum.all?(findings_for(report, "RCE.Compile"), &(&1["variable"] == "input"))
  end

  test "TLS imports respect file and function scopes and server confidence" do
    temp_fixture_file("basic", "lib/imported_tls.ex", """
    defmodule ImportedTLS do
      import :ssl, only: [connect: 3, listen: 2]
      def client(host), do: connect(host, 443, verify: :verify_none, versions: [:tlsv1 | configured()])
      def server(), do: listen(443, verify: :verify_none, versions: [:"tlsv1.1"])
      def modern(host, versions), do: connect(host, 443, verify: :verify_peer, versions: [:"tlsv1.3" | versions])
      def excluded(host) do
        import :ssl, except: [connect: 3]
        connect(host, 443, verify: :verify_none, versions: [:tlsv1])
      end
    end
    defmodule NeighborTLS do
      def client(host), do: connect(host, 443, verify: :verify_none, versions: [:tlsv1])
    end
    """)

    report = scan("basic", only: ["Config.WeakTLS", "Config.TLSVerify"])
    assert locations(report, "Config.WeakTLS") == [{3, "high"}, {4, "high"}]
    assert locations(report, "Config.TLSVerify") == [{3, "high"}, {4, "low"}]
  end

  test "top-level production TLS imports and imported Hackney calls are checked" do
    temp_fixture_file("basic", "config/prod.exs", """
    import :ssl, only: [connect: 3]
    connect(host, 443, verify: :verify_none, versions: [:tlsv1 | versions])
    """)

    temp_fixture_file("basic", "lib/imported_hackney.ex", """
    defmodule ImportedHackney do
      import :hackney, only: [get: 4, wt_connect: 2]
      def fetch(url), do: get(url, [], <<>>, insecure: true)
      def transport(url), do: wt_connect(url, verify: :verify_none)
      def secure(url), do: get(url, [], <<>>, insecure: false)
    end
    """)

    report = scan("basic", only: ["Config.WeakTLS", "Config.TLSVerify"])
    assert length(findings_for(report, "Config.WeakTLS")) == 1
    assert length(findings_for(report, "Config.TLSVerify")) == 3
  end

  test "unusual value shapes and sigil-shaped variables never abort a scan" do
    temp_fixture_file("basic", "lib/odd_security_values.ex", """
    defmodule OddSecurityValues do
      def sigil_variable(sigil_w), do: sigil_w
      def maps(input), do: Module.concat(%{name: input})
      def callback(input), do: Code.compile_string((fn -> input end).())
      def local(), do: Code.compile_string(__MODULE__.source())
      def file(input, root), do: Code.compile_file([input], root)
      def empty(root), do: Code.compile_file(<<>>, root)
    end
    """)

    report = scan("basic", only: ["DOS.ModuleConcat", "DOS.BinToAtom", "RCE.Compile"])
    assert length(findings_for(report, "DOS.ModuleConcat")) == 1
    assert length(findings_for(report, "RCE.Compile")) == 4
    assert [] = findings_for(report, "DOS.BinToAtom")
  end

  defp locations(report, check) do
    report |> findings_for(check) |> Enum.map(&{&1["line"], &1["confidence"]}) |> Enum.sort()
  end
end
