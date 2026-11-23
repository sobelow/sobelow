defmodule Sobelow.SafeWriteTest do
  use ExUnit.Case, async: false
  alias Sobelow.SafeWrite

  @tag :tmp_dir
  test "replacement preserves permissions and follows an existing symlink", %{tmp_dir: dir} do
    path = Path.join(dir, "config")
    link = Path.join(dir, "link")
    File.write!(path, "original")
    File.chmod!(path, 0o600)
    File.ln_s!(path, link)
    assert :ok = SafeWrite.write(link, "replacement")
    assert {:ok, ^path} = File.read_link(link)
    assert File.read!(path) == "replacement"
    assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600
    assert Enum.sort(File.ls!(dir)) == ["config", "link"]
  end

  @tag :tmp_dir
  test "failed replacements preserve existing content and remove temporary files", %{tmp_dir: dir} do
    path = Path.join(dir, "config")
    File.write!(path, "original")
    File.chmod!(path, 0o400)
    assert {:error, :eacces} = SafeWrite.write(path, "replacement")
    assert File.read!(path) == "original"
    assert File.ls!(dir) == ["config"]
    assert {:error, :eisdir} = SafeWrite.write(dir, "replacement")
  end

  @tag :tmp_dir
  test "symlink cycles return an error without leaving replacement files", %{tmp_dir: dir} do
    path = Path.join(dir, "cycle")
    File.ln_s!("cycle", path)
    assert {:error, :eloop} = SafeWrite.write(path, "replacement")
    assert File.ls!(dir) == ["cycle"]
  end

  @tag :tmp_dir
  test "invalid parent paths and missing parents retain filesystem error reasons", %{tmp_dir: dir} do
    path = Path.join(dir, "parent")
    File.write!(path, "original")
    assert {:error, :enotdir} = SafeWrite.write(Path.join(path, "child"), "replacement")

    assert {:error, :enoent} =
             SafeWrite.write(Path.join([dir, "missing", "child"]), "replacement")

    assert File.read!(path) == "original"

    assert_raise Sobelow.ScanError, ~r/Could not write/, fn ->
      SafeWrite.write!(path <> "/child", "replacement")
    end
  end

  @tag :tmp_dir
  test "an active writer blocks a competing clear, which can retry after cleanup", %{tmp_dir: dir} do
    parent = self()
    path = Path.join(dir, ".sobelow-skips")

    writer =
      Task.async(fn ->
        SafeWrite.transaction!(path, fn ->
          send(parent, {:locked, self()})
          receive do: (:publish -> SafeWrite.write!(path, "reviewed\n"))
        end)
      end)

    assert_receive {:locked, pid}, 1_000
    assert_raise Sobelow.ScanError, ~r/is locked/, fn -> Sobelow.SkipFile.clear(dir <> "/") end
    send(pid, :publish)
    assert Task.await(writer) == :ok
    assert File.read!(path) == "reviewed\n"
    assert :ok = Sobelow.SkipFile.clear(dir <> "/")
    assert :ok = Sobelow.SkipFile.clear(dir <> "/")
    assert File.ls!(dir) == []
  end

  @tag :tmp_dir
  test "replacement respects a symlinked directory followed by dot-dot", %{tmp_dir: dir} do
    File.mkdir_p!(Path.join(dir, "physical/child"))
    File.ln_s!("physical/child", Path.join(dir, "alias"))
    File.ln_s!("alias/../config", Path.join(dir, "link"))
    File.write!(Path.join(dir, "config"), "wrong target")

    assert :ok = SafeWrite.write(Path.join(dir, "link"), "replacement")
    assert File.read!(Path.join(dir, "physical/config")) == "replacement"
    assert File.read!(Path.join(dir, "config")) == "wrong target"
  end

  @tag :tmp_dir
  test "new files and dangling symlinks can be written atomically", %{tmp_dir: dir} do
    path = Path.join(dir, "created")
    link = Path.join(dir, "link")
    File.ln_s!("created", link)
    assert :ok = SafeWrite.write(link, "contents")
    assert File.read!(path) == "contents"
    assert File.read_link!(link) == "created"
    assert Enum.sort(File.ls!(dir)) == ["created", "link"]
  end

  if System.find_executable("mkfifo") do
    @tag :tmp_dir
    test "special files are refused rather than opened or replaced", %{tmp_dir: dir} do
      fifo = Path.join(dir, "fifo")
      assert {_, 0} = System.cmd("mkfifo", [fifo])
      assert {:error, :einval} = SafeWrite.write(fifo, "replacement")
      assert File.lstat!(fifo).type == :other
    end
  end
end
