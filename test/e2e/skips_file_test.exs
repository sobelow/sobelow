defmodule Sobelow.SkipsFileTest do
  @moduledoc """
  Coverage for the `.sobelow-skips` file written by `--mark-skip-all`.

  The file is committed to a project's repository, so its layout is part of the
  user-facing contract: it must round-trip, it must not lose lines it did not
  write, and it must stay ordered so that regenerating it produces a small diff.
  """
  use Sobelow.ScanCase

  @skips ".sobelow-skips"

  defp skips_path(fixture), do: Path.join(fixture_path(fixture), @skips)

  defp skip_lines(fixture) do
    skips_path(fixture)
    |> File.read!()
    |> String.split("\n")
    |> Enum.reject(&(&1 == ""))
  end

  # `--mark-skip-all` writes into the fixture app, so clean up after each test.
  setup do
    on_exit(fn -> File.rm_rf!(skips_path("basic")) end)
    :ok
  end

  defp mark_skips(fixture, opts \\ []) do
    scan_io(fixture, Keyword.merge([mark_skip_all: true], opts))
  end

  test "recorded skips suppress every finding on the next scan" do
    assert findings(scan("basic")) != []

    mark_skips("basic")

    assert findings(scan("basic", skip: true)) == []
  end

  test "entries are written sorted" do
    mark_skips("basic")

    lines = skip_lines("basic")

    assert lines != []
    assert lines == Enum.sort_by(lines, & &1)
  end

  # Sorting the raw strings would order line 10 before line 2, so an edit that
  # renumbers findings would reshuffle the file rather than just update it.
  test "entries in one file are ordered by line number numerically" do
    contents =
      Enum.map_join(2..12, "\n", fn _ ->
        ~s|  def a#{System.unique_integer([:positive])}(conn, %{"p" => p}), do: send_file(conn, 200, p)|
      end)

    temp_fixture_file(
      "basic",
      "lib/basic_web/controllers/many_controller.ex",
      "defmodule BasicWeb.ManyController do\n#{contents}\nend\n"
    )

    mark_skips("basic")

    line_numbers =
      "basic"
      |> skip_lines()
      |> Enum.filter(&String.contains?(&1, "many_controller.ex"))
      |> Enum.map(fn line ->
        [_type, location, _fingerprint] = String.split(line, ",")
        location |> String.split(":") |> List.last() |> String.to_integer()
      end)

    assert length(line_numbers) > 9, "expected enough findings to span one and two digits"
    assert line_numbers == Enum.sort(line_numbers)
  end

  describe "regenerating an existing file" do
    test "keeps the whole file sorted, not just the new entries" do
      mark_skips("basic")

      # A finding whose type sorts before everything already recorded.
      temp_fixture_file("basic", "lib/basic_web/controllers/ci_controller.ex", """
      defmodule BasicWeb.CIController do
        def run(conn, %{"cmd" => cmd}) do
          System.cmd(cmd, [])
          conn
        end
      end
      """)

      mark_skips("basic")

      lines = skip_lines("basic")

      assert Enum.any?(lines, &String.starts_with?(&1, "CI.System"))
      assert lines == Enum.sort_by(lines, & &1)
    end

    test "preserves comments at the top and legacy bare fingerprints at the end" do
      File.write!(skips_path("basic"), "# reviewed 2026-01-01\nDEADBEEF\n")

      mark_skips("basic")

      lines = skip_lines("basic")

      assert hd(lines) == "# reviewed 2026-01-01"
      assert List.last(lines) == "DEADBEEF"
    end

    test "does not duplicate entries when run twice with no new findings" do
      mark_skips("basic")
      first = skip_lines("basic")

      mark_skips("basic")

      assert skip_lines("basic") == first
    end
  end

  describe "--legacy-skips" do
    test "appends without rewriting what is already in the file" do
      File.write!(skips_path("basic"), "ZZZZZZZ\n")

      mark_skips("basic", legacy_skips: true)

      lines = skip_lines("basic")

      assert hd(lines) == "ZZZZZZZ", "existing content must not be reordered"
      assert length(lines) > 1
    end

    test "recorded skips still round-trip" do
      mark_skips("basic", legacy_skips: true)

      assert findings(scan("basic", skip: true)) == []
    end
  end
end
