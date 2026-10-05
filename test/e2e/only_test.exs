defmodule Sobelow.OnlyTest do
  @moduledoc """
  Coverage for `--only`, which runs a chosen set of checks or categories.

  It is implemented by ignoring every module it does not select, so these
  cases pin both the category-level and the check-level filtering.
  """
  use Sobelow.ScanCase

  test "a single check runs alone" do
    assert finding_modules(scan("basic", only: ["XSS.Raw"])) == ["XSS.Raw"]
  end

  test "a category runs all of its checks" do
    assert finding_modules(scan("basic", only: ["Traversal"])) == [
             "Traversal.FileModule",
             "Traversal.SendFile"
           ]
  end

  test "checks and categories combine" do
    assert finding_modules(scan("basic", only: ["SQL", "Config.Secrets"])) == [
             "Config.Secrets",
             "SQL.Query"
           ]
  end

  test "--ignore still applies on top" do
    report = scan("basic", only: ["Traversal"], ignored: ["Traversal.SendFile"])

    assert finding_modules(report) == ["Traversal.FileModule"]
  end

  describe "ignored_modules/0" do
    setup do
      original = Application.get_all_env(:sobelow)
      Application.put_env(:sobelow, :ignored, [])

      on_exit(fn ->
        Application.delete_env(:sobelow, :only)
        Application.put_all_env(sobelow: original)
      end)
    end

    test "keeps the parent category of a selected check" do
      Application.put_env(:sobelow, :only, ["XSS.Raw"])
      ignored = Sobelow.ignored_modules()

      refute Sobelow.XSS in ignored
      refute Sobelow.XSS.Raw in ignored
      assert Sobelow.XSS.SendResp in ignored
      assert Sobelow.SQL in ignored
    end

    test "ignores nothing extra when unset" do
      Application.delete_env(:sobelow, :only)

      assert Sobelow.ignored_modules() == []
    end
  end
end
