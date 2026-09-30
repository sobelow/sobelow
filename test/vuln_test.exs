defmodule SobelowTest.VulnTest do
  use ExUnit.Case

  @tag :tmp_dir
  test "dependency lockfile lookup never evaluates project code", %{tmp_dir: tmp_dir} do
    marker = Path.join(tmp_dir, "executed")
    lockfile = Path.join(tmp_dir, "mix.lock")
    File.write!(lockfile, "File.write!(#{inspect(marker)}, \"executed\")")

    assert Sobelow.Vuln.dependency_version(tmp_dir, "plug") == nil
    refute File.exists?(marker)
  end

  @tag :tmp_dir
  test "a dependency alias for another Hex package is not that package's version", %{
    tmp_dir: tmp_dir
  } do
    File.write!(Path.join(tmp_dir, "mix.lock"), ~s|%{"plug" => {:hex, :other_package, "1.3.1"}}|)
    assert Sobelow.Vuln.dependency_version(tmp_dir, "plug") == nil
  end

  @tag :tmp_dir
  test "a matching literal Hex package retains its locked version", %{tmp_dir: tmp_dir} do
    lockfile = Path.join(tmp_dir, "mix.lock")
    File.write!(lockfile, ~s|%{"plug" => {:hex, :plug, "1.3.1"}}|)
    assert Sobelow.Vuln.dependency_version(tmp_dir, "plug") == {lockfile, "1.3.1"}
  end

  @tag :tmp_dir
  test "nonliteral Hex package names are never evaluated", %{tmp_dir: tmp_dir} do
    marker = Path.join(tmp_dir, "executed")

    File.write!(
      Path.join(tmp_dir, "mix.lock"),
      ~s|%{"plug" => {:hex, File.write!(#{inspect(marker)}, "executed"), "1.3.1"}}|
    )

    assert Sobelow.Vuln.dependency_version(tmp_dir, "plug") == nil
    refute File.exists?(marker)
  end

  @tag :tmp_dir
  test "installed dependency version takes precedence over the lockfile", %{tmp_dir: tmp_dir} do
    mixfile = Path.join([tmp_dir, "deps", "plug", "mix.exs"])
    File.mkdir_p!(Path.dirname(mixfile))
    File.write!(mixfile, "defmodule Plug.Mixfile do\n  @version \"1.3.1\"\nend\n")
    File.write!(Path.join(tmp_dir, "mix.lock"), "%{\"plug\" => {:hex, :plug, \"1.3.0\"}}")

    assert Sobelow.Vuln.dependency_version(tmp_dir, "plug") == {mixfile, "1.3.1"}
  end
end
