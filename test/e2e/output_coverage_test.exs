defmodule Sobelow.OutputCoverageTest do
  use Sobelow.ScanCase, async: false

  for format <- ["json", "txt", "compact", "flycheck", "quiet"] do
    test "configuration findings are retained in #{format} output" do
      temp_fixture_file("basic", "lib/basic_web/router.ex", """
      defmodule BasicWeb.Router do
        use BasicWeb, :router
        pipeline :browser do
          plug :accepts, ~w(html json)
          plug :fetch_session
          plug :put_secure_browser_headers
        end
        scope "/", BasicWeb do
          get "/page", PageController, :show
          post "/page", PageController, :show
        end
      end
      """)

      {stdout, _stderr} = scan_io("basic", format: unquote(format), verbose: true)
      logged = Sobelow.FindingLog.log() |> Map.values() |> List.flatten()

      assert Enum.any?(logged, fn {_, finding, _} ->
               String.starts_with?(finding.type, "Config.CSP:") or
                 String.contains?(finding.type, "Config.CSP:")
             end)

      assert Enum.any?(logged, fn {_, finding, _} ->
               String.contains?(finding.type, "Config.CSRFRoute:")
             end)

      case unquote(format) do
        "json" -> assert Jason.decode!(stdout)["total_findings"] == length(logged)
        "quiet" -> assert stdout =~ "#{length(logged)} findings found"
        _ -> assert stdout =~ "Config.CSP:"
      end
    end
  end
end
