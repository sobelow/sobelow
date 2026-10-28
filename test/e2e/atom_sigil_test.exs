defmodule SobelowTest.E2E.AtomSigilTest do
  use Sobelow.ScanCase, async: false

  test "grades atom word sigils and supports existing skips and formats" do
    temp_fixture_file("basic", "lib/basic_web/controllers/atom_sigil_controller.ex", ~S'''
    defmodule BasicWeb.AtomSigilController do
      use BasicWeb, :controller
      def index(conn, %{"word" => word}), do: ~w(prefix_#{word})a
      # sobelow_skip ["DOS.BinToAtom"]
      def skipped(word), do: ~w(#{word})a
      def fixed(), do: ~w(fixed words)a
    end
    defmodule AtomSigilHelper do
      def words(word), do: ~w(#{word})a
    end
    ''')

    found = scan("basic", only: ["DOS.BinToAtom"], skip: true) |> findings_for("DOS.BinToAtom")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"]})) == [
             {3, "high"},
             {9, "low"}
           ]

    assert [] = scan("basic", ignored: ["DOS.BinToAtom"]) |> findings_for("DOS.BinToAtom")

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["DOS.BinToAtom"], format: format)
      assert output =~ if(format == "sarif", do: "SBLW011", else: "DOS.BinToAtom")
    end
  end

  test "known custom sigil owners do not borrow Kernel atom semantics" do
    temp_fixture_file("basic", "lib/custom_sigils.ex", ~S'''
    defmodule CustomSigils do
      import Kernel, except: [sigil_w: 2]
      def sigil_w(data, _modifiers), do: data
      def words(word), do: ~w(#{word})a
    end
    defmodule ImportedSigils do
      import Custom, only: [sigil_w: 2]
      def words(word), do: ~w(#{word})a
    end
    ''')

    assert [] = scan("basic", only: ["DOS.BinToAtom"]) |> findings_for("DOS.BinToAtom")
  end
end
