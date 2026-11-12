defmodule SobelowTest.E2E.RegexTest do
  use Sobelow.ScanCase, async: false

  test "resolves compile and escape aliases/imports without suppressing raw pattern fragments" do
    temp_fixture_file("basic", "lib/basic_web/controllers/regex_controller.ex", """
    defmodule BasicWeb.RegexController do
      use BasicWeb, :controller
      alias Regex, as: R
      import Regex, only: [compile: 1, escape: 1]
      def index(conn, %{"pattern" => pattern}) do
        pattern |> compile()
        R.compile!(pattern)
        compile(escape(pattern))
        R.compile!(R.escape(pattern))
        compile("^" <> escape(pattern) <> "$")
        :re.compile(pattern, [])
      end
      # sobelow_skip ["DOS.Regex"]
      def skipped(pattern), do: Regex.compile(pattern)
    end
    defmodule RegexHelper do
      def compile(pattern), do: Regex.compile(pattern)
    end
    """)

    found = scan("basic", only: ["DOS.Regex"], skip: true) |> findings_for("DOS.Regex")

    assert Enum.sort(Enum.map(found, &{&1["line"], &1["confidence"]})) ==
             [{6, "medium"}, {7, "medium"}, {11, "medium"}, {17, "low"}]

    for ignored <- ["DOS.Regex", "DOS"] do
      assert [] = scan("basic", ignored: [ignored]) |> findings_for("DOS.Regex")
    end

    for format <- ["txt", "compact", "flycheck", "github", "sarif"] do
      {output, _} = scan_io("basic", only: ["DOS.Regex"], format: format, skip: true)
      assert output =~ if(format == "sarif", do: "SBLW051", else: "DOS.Regex")
    end

    assert Sobelow.get_mod("DOS.Regex") == Sobelow.DOS.Regex
    assert Sobelow.DOS.details() =~ "DOS.Regex"
  end
end
