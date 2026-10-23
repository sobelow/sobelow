defmodule SobelowTest.E2E.DOSListToAtomTest do
  use Sobelow.ScanCase, async: false

  @controller_path "lib/basic_web/controllers/atom_controller.ex"

  defp skips_path, do: Path.join(fixture_path("basic"), ".sobelow-skips")

  setup do
    on_exit(fn -> File.rm_rf!(skips_path()) end)
    :ok
  end

  test "reports Elixir and Erlang calls as separate findings under one rule" do
    temp_fixture_file("basic", @controller_path, """
    defmodule BasicWeb.AtomController do
      use BasicWeb, :controller

      def show(conn, %{"a" => a, "b" => b, "c" => c}) do
        x = List.to_atom(a)
        y = :erlang.list_to_atom(b)
        z = c |> :erlang.list_to_atom()
        render(conn, :show, x: x, y: y, z: z)
      end
    end
    """)

    assert [
             %{"line" => 5, "variable" => "a", "type" => "DOS.ListToAtom: Unsafe `List.to_atom`"},
             %{
               "line" => 6,
               "variable" => "b",
               "type" => "DOS.ListToAtom: Unsafe `:erlang.list_to_atom`"
             },
             %{
               "line" => 7,
               "variable" => "c",
               "type" => "DOS.ListToAtom: Unsafe `:erlang.list_to_atom`"
             }
           ] = "basic" |> scan() |> atom_findings() |> Enum.sort_by(& &1["line"])
  end

  test "an existing `List.to_atom` skip still applies after an Erlang call is added" do
    path =
      temp_fixture_file("basic", @controller_path, """
      defmodule BasicWeb.AtomController do
        use BasicWeb, :controller

        def show(conn, %{"a" => a, "b" => b}) do
          render(conn, :show, x: List.to_atom(a))
        end
      end
      """)

    scan_io("basic", mark_skip_all: true)

    File.write!(path, """
    defmodule BasicWeb.AtomController do
      use BasicWeb, :controller

      def show(conn, %{"a" => a, "b" => b}) do
        render(conn, :show, x: List.to_atom(a))
        render(conn, :show, y: :erlang.list_to_atom(b))
      end
    end
    """)

    assert [%{"line" => 6, "variable" => "b"}] =
             "basic" |> scan(skip: true) |> atom_findings()
  end

  defp atom_findings(report) do
    report
    |> findings_for("DOS.ListToAtom")
    |> Enum.filter(&String.ends_with?(&1["file"], "atom_controller.ex"))
  end
end
