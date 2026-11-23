defmodule Sobelow.ScanStateTest do
  use ExUnit.Case, async: false
  alias Sobelow.{Parse, Scan}

  @tag :tmp_dir
  test "source reads and ASTs are consistent within a scan and refreshed on the next scan", %{
    tmp_dir: dir
  } do
    path = Path.join(dir, "source.ex")
    File.write!(path, "first()")

    Scan.with_scan(fn ->
      first = Parse.ast(path)
      File.write!(path, "second()")
      assert Parse.ast(path) == first
      assert Scan.stats().source_reads == 1
    end)

    Scan.with_scan(fn ->
      assert {:second, _, []} = Parse.ast(path)
    end)
  end

  @tag :tmp_dir
  test "scan state is released on errors and outside parsing remains uncached", %{tmp_dir: dir} do
    path = Path.join(dir, "source.ex")
    assert_raise RuntimeError, "stop", fn -> Scan.with_scan(fn -> raise "stop" end) end
    refute Scan.active?()
    File.write!(path, "first()")
    assert {:first, _, []} = Parse.ast(path)
    File.write!(path, "second()")
    assert {:second, _, []} = Parse.ast(path)
  end

  @tag :tmp_dir
  test "dependency checks share the original lockfile snapshot", %{tmp_dir: dir} do
    path = Path.join(dir, "mix.lock")
    File.write!(path, ~s|%{"plug" => {:hex, :plug, "1.2.0"}, "ecto" => {:hex, :ecto, "2.0.0"}}|)

    Scan.with_scan(fn ->
      assert {^path, "1.2.0"} = Sobelow.Vuln.dependency_version(dir, "plug")
      File.write!(path, "%{}")
      assert {^path, "2.0.0"} = Sobelow.Vuln.dependency_version(dir, "ecto")
      assert {^path, "1.2.0"} = Sobelow.Vuln.dependency_version(dir, "plug")
      assert Scan.stats().source_reads == 1
    end)

    Scan.with_scan(fn -> assert Sobelow.Vuln.dependency_version(dir, "plug") == nil end)
  end

  test "a competing scan waits for its predecessor, even when the predecessor raises" do
    parent = self()

    first =
      Task.async(fn ->
        assert_raise RuntimeError, "stop", fn ->
          Scan.exclusive(fn ->
            Scan.exclusive(fn -> send(parent, :first_entered) end)
            receive do: (:release -> raise "stop")
          end)
        end
      end)

    assert_receive :first_entered, 1_000

    second =
      Task.async(fn ->
        send(parent, :second_ready)
        Scan.exclusive(fn -> send(parent, :second_entered) end)
      end)

    assert_receive :second_ready, 1_000
    refute_receive :second_entered
    send(first.pid, :release)
    Task.await(first)
    assert_receive :second_entered, 1_000
    Task.await(second)
  end

  test "parallel preparation retains order, shares cache and restores worker state" do
    Scan.with_scan(fn ->
      values =
        Scan.map(Enum.to_list(1..64), fn value ->
          assert Scan.active?()
          Scan.fetch({:value, value}, fn -> value * 2 end)
        end)

      assert values == Enum.map(1..64, &(&1 * 2))
      assert Scan.stats().cache_misses == 64
    end)

    refute Scan.active?()
  end

  test "worker options and ignored fingerprints use the scan snapshot and then refresh" do
    original = Application.get_all_env(:sobelow)

    on_exit(fn ->
      for {key, _} <- Application.get_all_env(:sobelow), do: Application.delete_env(:sobelow, key)
      for {key, value} <- original, do: Application.put_env(:sobelow, key, value)
    end)

    Application.put_env(:sobelow, :ignored, ["Traversal.FileModule"])
    Application.put_env(:sobelow, :root, ".")
    Application.put_env(:sobelow, :threshold, :low)
    {:ok, _} = Sobelow.Fingerprint.start_link()
    Sobelow.Fingerprint.put_ignore("legacy")

    Scan.with_scan(fn ->
      Scan.configure([Sobelow.Traversal])
      Application.put_env(:sobelow, :threshold, :high)

      assert Scan.map([1, 2], fn _ ->
               assert Sobelow.get_env(:threshold) == :low
               assert Scan.ignored_fingerprint?("legacy")
               refute Scan.ignored_fingerprint?("new")

               refute Sobelow.Traversal.FileModule in Sobelow.allowed_checks(
                        Sobelow.Traversal,
                        Sobelow.Traversal.finding_modules()
                      )

               :ok
             end) == [:ok, :ok]
    end)

    assert Sobelow.get_env(:threshold) == :high

    Scan.with_scan(fn ->
      Scan.configure([Sobelow.Traversal])
      assert Sobelow.get_env(:threshold) == :high
    end)
  end

  test "concurrent cache misses return the value that was published" do
    parent = self()

    Scan.with_scan(fn ->
      table = Scan.current()

      start = fn value ->
        Task.async(fn ->
          Scan.attach(table, fn ->
            Scan.fetch(:shared, fn ->
              send(parent, {:ready, self()})
              receive do: (:publish -> value)
            end)
          end)
        end)
      end

      first = start.(:first)
      second = start.(:second)
      assert_receive {:ready, pid}, 1_000
      assert_receive {:ready, other}, 1_000
      assert MapSet.new([pid, other]) == MapSet.new([first.pid, second.pid])

      send(first.pid, :publish)
      assert Task.await(first) == :first
      send(second.pid, :publish)
      assert Task.await(second) == :first
      assert Scan.fetch(:shared, fn -> flunk("cache entry lost") end) == :first
    end)
  end

  test "discovery finalizes unselected files without overwriting terminal states" do
    Scan.with_scan(fn ->
      Scan.discover(~w(ignored external parsed missing), &(&1 == "ignored"))
      Scan.record("ignored", :unparseable, "should never parse")
      Scan.record("parsed", :scanned)
      Scan.record("parsed", :unparseable, "inline template")
      Scan.record("parsed", :scanned)
      Scan.record("missing", :unreadable, "missing")
      Scan.finish_discovery()
      Scan.finish_discovery()

      assert %{counts: counts, diagnostics: diagnostics} = Scan.report()

      assert counts == %{
               discovered: 4,
               ignored: 1,
               pending: 0,
               scanned: 0,
               unreadable: 1,
               unparseable: 1,
               unselected: 1
             }

      assert Enum.map(diagnostics, & &1.message) == ["missing", "inline template"]
    end)
  end

  test "cache statistics sum hits from all preparation workers" do
    Scan.with_scan(fn ->
      assert Scan.fetch(:shared, fn -> :value end) == :value

      Scan.map(Enum.to_list(1..64), fn _ ->
        assert Scan.fetch(:shared, fn -> flunk("cached value was lost") end) == :value
      end)

      assert Scan.stats().cache_hits == 64
      assert Scan.stats().cache_misses == 1
    end)
  end
end
