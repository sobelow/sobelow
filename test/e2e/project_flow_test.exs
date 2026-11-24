defmodule Sobelow.ProjectFlowTest do
  use Sobelow.ScanCase, async: false

  @controller "lib/basic_web/controllers/flow_controller.ex"
  @context "lib/basic/reporting.ex"
  @live "lib/basic_web/live/preview_live.ex"
  @template "lib/basic_web/live/preview_live.html.heex"

  defp controller(body) do
    temp_fixture_file("basic", @controller, """
    defmodule BasicWeb.FlowController do
      use BasicWeb, :controller
    #{body}
    end
    """)
  end

  defp scan_flows(check, file) do
    {stdout, _} = scan_io("basic", format: "sarif", only: [check])
    [run] = Jason.decode!(stdout)["runs"]

    for r <- run["results"], [loc] = r["locations"], {^file, line} <- [site(loc)] do
      steps =
        for flow <- Map.get(r, "codeFlows", []),
            thread <- flow["threadFlows"],
            %{"location" => loc} <- thread["locations"],
            do: {site(loc), loc["message"]["text"]}

      {line, steps}
    end
  end

  defp site(%{"physicalLocation" => l}),
    do: {l["artifactLocation"]["uri"], l["region"]["startLine"]}

  defp lines(results), do: Enum.sort(for({n, [_ | _]} <- results, do: n))

  test "an assignment followed by a return through an aliased context reaches only SQL text" do
    temp_fixture_file("basic", @context, """
    defmodule Basic.Reporting do
      def run(text), do: Repo.query!(text, [])
      def sql(value), do: prefix(value)
      defp prefix(value), do: "SELECT " <> value
      def fixed(_value), do: "SELECT 1"
    end
    """)

    controller("""
      alias Basic.Reporting, as: Reports
      def show(_, params) do
        part = params["column"]
        text = Reports.sql(part)
        Reports.run(text)
        Repo.query(text, [])
        text = Reports.fixed(part)
        Repo.query(text, [])
        Repo.query("SELECT $1", [part])
      end
    """)

    results = scan_flows("SQL.Query", @controller)
    assert [{8, steps}, {10, []}] = results
    assert [{{@controller, 4}, _} | _] = steps
    assert Enum.any?(steps, &match?({{@context, 4}, _}, &1))
    assert Enum.any?(steps, fn {_, msg} -> msg =~ "sql/1 returns" end)
    assert [{2, context_steps}] = scan_flows("SQL.Query", @context)
    assert {{@context, 2}, _} = List.last(context_steps)
  end

  test "adapter query, stream, and pipes trace the effective SQL argument only" do
    controller("""
      alias Ecto.Adapters.SQL
      def show(_, params) do
        text = params["text"]
        SQL.query(Repo, text, [])
        Repo |> SQL.query!("SELECT $1", [text])
        Repo |> SQL.stream(text, [])
      end
    """)

    assert lines(scan_flows("SQL.Query", @controller)) == [6]
    assert lines(scan_flows("SQL.Stream", @controller)) == [8]
  end

  test "map and tuple pattern matching preserves field identity and the selected case arm" do
    controller("""
      def show(_, params) do
        attrs = %{name: params["name"], role: "reader"}
        {:ok, %{name: name, role: role}} = {:ok, attrs}
        File.read(role)
        File.read(name)
        path = case params["kind"] do
          "from_form" -> attrs.name
          _ -> "fixed"
        end
        File.read(path)
        other = %{attrs | name: "fixed"}
        File.read(other.name)
      end
    """)

    results = scan_flows("Traversal.FileModule", @controller)
    assert lines(results) == [7, 12]
    assert {12, steps} = List.keyfind(results, 12, 0)
    assert Enum.any?(steps, fn {site, msg} -> site == {@controller, 9} and msg =~ "case" end)
  end

  test "with matches tuple tags, isolates else bindings, and discards impossible paths" do
    controller("""
      def show(_, params) do
        tagged = {:ok, params["file"]}
        path = with {:ok, x} <- tagged do
          x
        else
          _ -> "fixed"
        end
        File.read(path)
        with {:error, other} <- tagged do
          File.read(other)
        else
          {:ok, recovered} -> File.read(recovered)
        end
      end
    """)

    results = scan_flows("Traversal.FileModule", @controller)
    assert lines(results) == [10, 14]
    assert {14, steps} = List.keyfind(results, 14, 0)
    assert Enum.any?(steps, fn {_, msg} -> msg =~ "with else" end)
  end

  test "an event reaches only the returned socket's matching inline raw assign" do
    temp_fixture_file("basic", @live, """
    defmodule BasicWeb.PreviewLive do
      use BasicWeb, :live_view
      def handle_event("preview", %{"body" => body}, socket) do
        assign(socket, :discarded, body)
        socket = socket |> assign(:body, body) |> assign(:title, body)
        {:noreply, assign(socket, :title, "fixed")}
      end
      def render(assigns) do
        ~H\"\"\"
        <p>{raw(@body)}</p>
        <p>{raw(@discarded)}</p>
        <p>{raw(@title)}</p>
        \"\"\"
      end
    end
    """)

    results = scan_flows("XSS.Raw", @live)
    assert lines(results) == [10]
    assert {10, path} = List.keyfind(results, 10, 0)
    assert Enum.any?(path, fn {site, msg} -> site == {@live, 5} and msg =~ "@body" end)
  end

  test "a reply socket connects to its colocated template, with assigns isolated by view" do
    temp_fixture_file("basic", @live, """
    defmodule BasicWeb.PreviewLive do
      use Phoenix.LiveView
      def handle_event("preview", values, socket) do
        socket = Phoenix.Component.assign(socket, :body, values["text"])
        {:reply, %{}, socket}
      end
    end
    """)

    temp_fixture_file("basic", @template, "{@body |> raw()}\n{raw(@title)}")
    other = "lib/basic_web/live/other_live.html.heex"
    temp_fixture_file("basic", other, "{raw(@body)}")
    assert [{1, [_ | _]}, {2, []}] = scan_flows("XSS.Raw", @template)
    assert [{1, []}] = scan_flows("XSS.Raw", other)
  end

  test "summaries preserve the selected fields through imports and qualified calls" do
    temp_fixture_file("basic", @context, """
    defmodule Elixir.Basic.Reporting do
      def field(record), do: record.profile["path"]
      def fixed(record), do: record.profile["default"]
      defp private_value(value), do: value
      def guarded(value) when is_binary(value), do: value
      defmacro generated(value), do: value
    end
    """)

    controller("""
      import Basic.Reporting, only: [field: 1]
      alias Basic.Reporting
      def show(_, params) do
        attrs = %{profile: %{"path" => params["key"], "default" => "fixed"}}
        File.read(field(attrs))
        File.read(Reporting.fixed(attrs))
        File.read(Reporting.private_value(params["key"]))
        File.read(Reporting.guarded(params["key"]))
        File.read(Reporting.generated(params["key"]))
        File.read(__MODULE__.identity(params["key"]))
      end
      def identity(value), do: value
    """)

    results = scan_flows("Traversal.FileModule", @controller)
    assert lines(results) == [7, 12]
    assert {7, path} = List.keyfind(results, 7, 0)
    assert Enum.any?(path, fn {site, msg} -> site == {@context, 2} and msg =~ "binds" end)
  end

  test "literal Map keys and boolean branches keep fixed and request fields separate" do
    controller("""
      def show(_, params) do
        record = Map.put(%{text: "fixed"}, :path, params["path"])
        with {:ok, path} <- Map.fetch(record, :path),
             value = if(params["flag"], do: path, else: "fixed") do
          File.read(value)
        end
        File.read(Map.get(record, :text))
        File.read(Map.get(record, :missing, params["fallback"]))
        false && File.read(params["dead"])
        unless false do
          File.read(params["live"])
        end
      end
    """)

    results = scan_flows("Traversal.FileModule", @controller)
    assert lines(results) == [7, 10, 13]
    assert {7, path} = List.keyfind(results, 7, 0)
    assert Enum.any?(path, fn {_, msg} -> msg =~ "if selects its do branch" end)
  end

  test "nested LiveView assign fields and socket return tags control raw paths" do
    temp_fixture_file("basic", @live, """
    defmodule BasicWeb.PreviewLive do
      use Phoenix.LiveView
      def handle_event("preview", values, socket) do
        profile = %{name: values["name"], info: %{"note" => values["note"]}, title: "fixed"}
        {:noreply, assign(socket, :profile, profile)}
      end
      def handle_event("draft", values, socket), do: {:ok, assign(socket, :draft, values)}
    end
    """)

    temp_fixture_file("basic", @template, """
    {raw(@profile.name)}
    {raw(@profile.info["note"])}
    {raw(@profile.title)}
    {raw(@draft)}
    {raw(display(@profile).text)}
    """)

    results = scan_flows("XSS.Raw", @template)
    assert lines(results) == [1, 2]
    assert {2, [{{@live, 3}, msg} | _]} = List.keyfind(results, 2, 0)
    assert msg =~ "event payload"
  end

  test "destructured helper parameters match only the tagged branch and selected field" do
    controller("""
      def show(_, params) do
        tag = if params["flag"], do: {:ok, %{path: params["path"]}}, else: {:skip, %{path: "fixed"}}
        File.read(selected(tag))
        File.read(selected({:ok, %{path: "fixed", extra: params}}))
        selected({:skip, %{path: params}})
        File.read(params["unreachable"])
      end
      defp selected({:ok, %{path: path}}), do: path
    """)

    assert lines(scan_flows("Traversal.FileModule", @controller)) == [5]
  end

  test "ambiguous imports, dynamic calls and recursive returns leave no helper evidence" do
    temp_fixture_file("basic", @context, """
    defmodule Basic.Reporting do
      def field(value), do: value
      def loop(value), do: loop(value)
    end
    defmodule Basic.Other do
      def field(_value), do: "fixed"
    end
    """)

    controller("""
      import Basic.Reporting, only: [field: 1]
      import Basic.Other, only: [field: 1]
      def show(_, params) do
        File.read(field(params["path"]))
        File.read(apply(Basic.Reporting, params["fun"], [params]))
        File.read(Basic.Reporting.loop(params["path"]))
        File.read(Basic.Reporting.field(params["path"]))
      end
    """)

    results = scan_flows("Traversal.FileModule", @controller)
    assert length(results) == 4
    assert lines(results) == [9]
  end

  test "a nested module's implicit alias takes effect at its declaration" do
    temp_fixture_file("basic", @context, """
    defmodule Shape do
      def field(_), do: "fixed"
    end
    """)

    controller("""
      def before_nested(_, p), do: File.read(Shape.field(p["key"]))
      defmodule Shape do
        def field(value), do: value
      end
      def after_nested(_, p) do
        File.read(Shape.field(p["key"]))
        File.read(Elixir.Shape.field(p["key"]))
        alias Elixir.Shape, as: Shape
        File.read(Shape.field(p["key"]))
      end
    """)

    results = scan_flows("Traversal.FileModule", @controller)
    assert length(results) == 4
    assert lines(results) == [8]
  end
end
