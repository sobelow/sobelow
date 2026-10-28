defmodule SobelowTest.E2E.ConsultTest do
  use Sobelow.ScanCase, async: false

  test "grades dynamic file selection and merges both path_consult arguments" do
    temp_fixture_file("basic", "lib/basic_web/controllers/consult_controller.ex", """
    defmodule BasicWeb.ConsultController do
      use BasicWeb, :controller
      def index(conn, %{"file" => file, "paths" => paths}) do
        :file.consult(file)
        paths |> :file.path_consult(file)
        :file.path_consult(paths, "settings.config")
        :file.consult(local_path())
        :file.path_consult(paths, "/etc/settings.config")
      end
    end
    """)

    temp_fixture_file("basic", "lib/term_reader.ex", """
    defmodule TermReader do
      def read(file), do: :file.consult(file)
    end
    """)

    found = scan("basic") |> findings_for("DOS.Consult")
    assert Enum.frequencies_by(found, & &1["confidence"]) == %{"medium" => 3, "low" => 2}
    controller = Enum.filter(found, &String.ends_with?(&1["file"], "consult_controller.ex"))
    assert Enum.sort(Enum.map(controller, & &1["line"])) == [4, 5, 6, 7]
  end

  test "supports category ignore, function skips, and SARIF registration" do
    temp_fixture_file("basic", "lib/term_reader.ex", """
    defmodule TermReader do
      def read(file), do: :file.consult(file)
      # sobelow_skip ["DOS.Consult"]
      def skipped(paths), do: :file.path_consult(paths, "settings.config")
    end
    """)

    assert [_, _] = scan("basic") |> findings_for("DOS.Consult")
    assert [_] = scan("basic", skip: true) |> findings_for("DOS.Consult")

    for ignored <- ["DOS.Consult", "DOS"] do
      assert [] = scan("basic", ignored: [ignored]) |> findings_for("DOS.Consult")
    end

    {output, _} = scan_io("basic", format: "sarif", skip: true)
    [run] = Jason.decode!(output)["runs"]
    assert Enum.count(run["results"], &(&1["ruleId"] == "SBLW037")) == 1
  end

  test "reports interpolated single-quoted charlists with parameter confidence" do
    temp_fixture_file("basic", "lib/basic_web/controllers/consult_controller.ex", ~S'''
    defmodule BasicWeb.ConsultController do
      use BasicWeb, :controller
      def index(conn, %{"file" => file}) do
        :file.consult('#{file}/settings.config')
        '#{file}/settings.config' |> :file.consult()
        :file.path_consult(['config'], '#{file}/settings.config')
        :file.path_consult(['#{file}/config'], 'settings.config')
        ['#{file}/config'] |> :file.path_consult('settings.config')
      end
    end
    ''')

    found = scan("basic") |> findings_for("DOS.Consult")
    assert Enum.sort(Enum.map(found, & &1["line"])) == [4, 5, 6, 7, 8]
    assert Enum.all?(found, &(&1["confidence"] == "medium"))
  end
end
