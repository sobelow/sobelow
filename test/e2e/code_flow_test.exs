defmodule Sobelow.CodeFlowTest do
  use Sobelow.ScanCase, async: false

  @controller "lib/basic_web/controllers/trace_controller.ex"
  @template "lib/basic_web/controllers/trace_html/show.html.heex"

  test "a render links only matching raw uses, in source order" do
    temp_fixture_file("basic", @controller, """
    defmodule BasicWeb.TraceController do
      use BasicWeb, :controller
      def show(conn, %{"name" => name}), do: render(conn, :show, name: name)
    end
    """)

    template =
      temp_fixture_file("basic", @template, """
      {raw(@other)}
      {raw(@name)}
      {@name |> raw()}
      """)

    results = results("XSS.Raw")
    assert [render] = at(results, @controller)
    assert render["level"] == "error"
    assert site(hd(render["locations"])) == {@controller, 3}

    assert Enum.map(paths(render), fn path -> Enum.map(path, &site/1) end) == [
             [{@controller, 3}, {@template, 2}],
             [{@controller, 3}, {@template, 3}]
           ]

    assert Enum.all?(List.flatten(paths(render)), &(&1["message"]["text"] =~ "@name"))
    assert Enum.all?(at(results, @template), &(paths(&1) == []))

    {verbose, _} = scan_io("basic", format: "txt", only: ["XSS.Raw"], verbose: true)

    assert Regex.scan(~r/^  (.+\.heex:\d+)(?::\d+)?  raw outputs @name$/m, verbose,
             capture: :all_but_first
           ) ==
             [["#{@template}:2"], ["#{@template}:3"]]

    File.write!(template, "{raw(@other)}")
    assert at(results("XSS.Raw"), @controller) == []
  end

  test "verbose text prints the SARIF steps in order above the highlighted sink" do
    temp_fixture_file("no_router", @controller, """
    defmodule BasicWeb.TraceController do
      use BasicWeb, :controller
      def show(_, params) do
        path = params["path"]
        Reports.read(path, "fixed")
      end
    end
    """)

    temp_fixture_file("no_router", "lib/reports.ex", """
    defmodule Reports do
      def read(path, fixed) do
        File.read(path)
        File.read(fixed)
      end
    end
    """)

    opts = [only: ["Traversal.FileModule"], router: :none]
    {sarif, _} = scan_io("no_router", [format: "sarif"] ++ opts)
    [traced, untraced] = Jason.decode!(sarif)["runs"] |> hd() |> Map.fetch!("results")
    [steps] = paths(traced)
    assert paths(untraced) == []
    assert site(List.last(steps)) == {"lib/reports.ex", 3}

    expected =
      Enum.map_join(steps, "\n", fn loc ->
        {file, line} = site(loc)
        col = loc["physicalLocation"]["region"]["startColumn"]
        "  #{file}:#{line}:#{col}  #{loc["message"]["text"]}"
      end)

    {verbose, _} = scan_io("no_router", [format: "txt", verbose: true] ++ opts)
    [first, second, _] = String.split(verbose, Sobelow.Print.finding_break())
    [_, snippet] = String.split(first, "Possible path\n" <> expected)
    assert snippet =~ IO.ANSI.light_magenta() <> "File.read(path)"
    assert second =~ IO.ANSI.light_magenta() <> "File.read(fixed)"
    refute second =~ "Possible path"

    {plain, _} = scan_io("no_router", [format: "txt"] ++ opts)
    refute plain =~ "Possible path"
    assert Sobelow.FindingLog.counts() == %{low: 2, medium: 0, high: 0}
    assert Enum.all?(Sobelow.FindingLog.log().low, fn {_, f, _} -> f.code_flows == [] end)
  end

  test "verbose preserves each non-text report" do
    for format <- ~w(json sarif github quiet compact flycheck) do
      opts = [format: format, only: ["Traversal.SendFile"]]
      {normal, _} = scan_io("basic", opts)
      {verbose, _} = scan_io("basic", [verbose: true] ++ opts)
      assert verbose == normal, format

      [{_, finding, _}] = Sobelow.FindingLog.log().high
      assert finding.code_flows != [] == (format == "sarif"), format
    end
  end

  test "only a request value passed to the file path slot adds a trace" do
    file = temp_fixture_file("basic", @controller, "")

    hashes =
      for {arguments, traced?} <- [
            {~s(params["path"], "log"), true},
            {~s("fixed", "log"), false},
            {~s("fixed", params["path"]), false}
          ] do
        File.write!(file, """
        defmodule BasicWeb.TraceController do
          use BasicWeb, :controller
          def show(_conn, params), do: read_path(#{arguments})
          defp read_path(path, label) do
            File.write(path, label)
          end
        end
        """)

        assert [result] = at(results("Traversal.FileModule"), @controller)
        assert result["level"] == "error"
        assert site(hd(result["locations"])) == {@controller, 5}

        if traced? do
          assert [[caller, parameter, sink]] = paths(result)

          assert Enum.map([caller, parameter, sink], &site/1) == [
                   {@controller, 3},
                   {@controller, 4},
                   {@controller, 5}
                 ]

          assert caller["message"]["text"] =~ ~s(params["path"] as argument 1 of read_path/2)
          assert parameter["message"]["text"] =~ "Argument 1 binds path"
          assert sink["message"]["text"] =~ "path is used as argument 1"
        else
          refute Map.has_key?(result, "codeFlows")
        end

        result["partialFingerprints"]["primaryLocationLineHash"]
      end

    assert [hash] = Enum.uniq(hashes)
    assert is_binary(hash)
  end

  test "piped controller and helper calls use their effective argument positions" do
    temp_fixture_file("basic", @controller, """
    defmodule BasicWeb.TraceController do
      use BasicWeb, :controller
      def show(conn, _params), do: conn |> deliver(conn.params["path"])
      defp deliver(conn, path), do: conn |> send_file(200, path)
    end
    """)

    assert [result] = at(results("Traversal.SendFile"), @controller)
    assert [[caller, parameter, sink]] = paths(result)
    assert caller["message"]["text"] =~ "argument 2 of deliver/2"
    assert parameter["message"]["text"] =~ "Argument 2 binds path"
    assert sink["message"]["text"] =~ "path is used as argument 3"
  end

  test "the source and destination of a two-path operation get independent evidence" do
    temp_fixture_file("basic", @controller, """
    defmodule BasicWeb.TraceController do
      use BasicWeb, :controller
      def show(_, %{"to" => dest}), do: copy_path("fixed", dest)
      def other(_, params), do: copy_path("fixed", params["to"])
      defp copy_path(source, dest), do: File.cp(source, dest)
    end
    """)

    copies = at(results("Traversal.FileModule"), @controller)
    assert length(copies) == 2
    assert [[], [[caller, parameter, sink]]] = Enum.sort(Enum.map(copies, &paths/1))
    assert site(caller) == {@controller, 3}
    assert parameter["message"]["text"] =~ "Argument 2 binds dest"
    assert sink["message"]["text"] =~ "dest is used as argument 2"
  end

  test "a qualified sibling call resolves while ambiguous, rebound and quoted paths stay plain" do
    temp_fixture_file("basic", @controller, """
    defmodule BasicWeb.TraceController do
      use BasicWeb, :controller
      def show(_, %{"path" => path}) do
        Other.read(path)
        multiple(path)
        rebound(path)
        quote do: quoted(unquote(path))
      end
      defp multiple(:special), do: :skip
      defp multiple(path), do: File.read(path)
      defp rebound(path) do
        path = setting()
        File.read(path)
      end
      defp quoted(path), do: File.read(path)
    end
    defmodule Other do
      def read(path), do: File.read(path)
    end
    """)

    results = at(results("Traversal.FileModule"), @controller)
    assert length(results) == 4
    assert [qualified] = Enum.reject(results, &(paths(&1) == []))
    assert site(hd(qualified["locations"])) == {@controller, 18}
  end

  defp results(check) do
    {stdout, _} = scan_io("basic", format: "sarif", only: [check])
    Jason.decode!(stdout)["runs"] |> hd() |> Map.fetch!("results")
  end

  defp at(results, file), do: Enum.filter(results, &(elem(site(hd(&1["locations"])), 0) == file))

  defp site(%{"physicalLocation" => location}) do
    {location["artifactLocation"]["uri"], location["region"]["startLine"]}
  end

  defp paths(result) do
    for %{"threadFlows" => [%{"locations" => locations}]} <- Map.get(result, "codeFlows", []),
        do: Enum.map(locations, &Map.fetch!(&1, "location"))
  end
end
