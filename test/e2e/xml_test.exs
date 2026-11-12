defmodule SobelowTest.E2E.XMLTest do
  use Sobelow.ScanCase, async: false

  test "tracks explicit options through imports and pipes and retains normal output behavior" do
    temp_fixture_file("basic", "lib/basic_web/controllers/xml_controller.ex", """
    defmodule BasicWeb.XMLController do
      use BasicWeb, :controller
      import :xmerl_scan, only: [string: 2]
      def index(conn, %{"xml" => xml}) do
        xml |> string(allow_entities: true)
        :xmerl_sax_parser.stream(xml, external_entities: :file)
        :xmerl_scan.string(xml, allow_entities: false)
        :xmerl_sax_parser.stream(xml, [])
      end
      # sobelow_skip ["DOS.XML"]
      def skipped(xml), do: :xmerl_scan.string(xml, allow_entities: true)
    end
    defmodule XMLHelper do
      def parse(xml), do: :xmerl_scan.string(xml, allow_entities: true)
    end
    """)

    found = scan("basic", only: ["DOS.XML"], skip: true) |> findings_for("DOS.XML")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"]})) ==
             [{5, "medium"}, {6, "medium"}, {14, "low"}]

    for ignored <- ["DOS.XML", "DOS"] do
      assert [] = scan("basic", ignored: [ignored]) |> findings_for("DOS.XML")
    end

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["DOS.XML"], format: format, skip: true)
      assert output =~ if(format == "sarif", do: "SBLW049", else: "DOS.XML")
    end

    assert Sobelow.get_mod("DOS.XML") == Sobelow.DOS.XML
    assert Sobelow.DOS.details() =~ "DOS.XML"
  end
end
