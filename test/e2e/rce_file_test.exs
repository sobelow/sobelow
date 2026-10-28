defmodule SobelowTest.E2E.RCEFileTest do
  use Sobelow.ScanCase, async: false

  setup do
    temp_fixture_file("basic", "lib/basic_web/controllers/script_controller.ex", """
    defmodule BasicWeb.ScriptController do
      use BasicWeb, :controller
      def index(conn, %{"file" => file, "paths" => paths}) do
        :file.script(file)
        paths |> :file.path_script(file)
        :file.path_eval(paths, "startup.erl")
        :file.eval(local_path())
        &:file.script/1
        :file.path_script(paths, "/opt/app/startup.erl")
        :file.eval("startup.erl", file)
        conn
      end
      # sobelow_skip ["RCE.File"]
      def skipped(file), do: :file.eval(file)
    end
    """)

    temp_fixture_file("basic", "lib/script_reader.ex", """
    defmodule ScriptReader do
      def read(file), do: :file.script(file)
    end
    """)

    :ok
  end

  test "grades selection conservatively, deduplicates and preserves locations" do
    found = scan("basic", skip: true) |> findings_for("RCE.File")
    assert Enum.frequencies_by(found, & &1["confidence"]) == %{"medium" => 3, "low" => 3}
    controller = Enum.filter(found, &String.ends_with?(&1["file"], "script_controller.ex"))
    assert Enum.sort(Enum.map(controller, & &1["line"])) == [4, 5, 6, 7, 8]
    assert Sobelow.get_mod("RCE.File") == Sobelow.RCE.File
    assert Sobelow.RCE.File.id() == "SBLW041"
    ids = Enum.map(Sobelow.finding_modules(), & &1.id())
    assert length(ids) == length(Enum.uniq(ids))
  end

  test "supports ignores, skips, thresholds and renderers" do
    assert length(scan("basic") |> findings_for("RCE.File")) == 7

    for ignored <- ["RCE", "RCE.File"] do
      assert [] = scan("basic", ignored: [ignored]) |> findings_for("RCE.File")
    end

    assert [] = scan("basic", threshold: :high) |> findings_for("RCE.File")

    for format <- ["txt", "compact", "flycheck", "github"] do
      {output, _} = scan_io("basic", format: format)
      assert output =~ "RCE.File"
    end

    {output, _} = scan_io("basic", format: "sarif", skip: true)
    [run] = Jason.decode!(output)["runs"]
    assert Enum.count(run["results"], &(&1["ruleId"] == "SBLW041")) == 6
    assert Enum.any?(run["tool"]["driver"]["rules"], &(&1["id"] == "SBLW041"))
  end
end
