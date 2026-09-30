defmodule SobelowTest do
  use ExUnit.Case
  doctest Sobelow

  test "malformed version-check responses cannot abort a scan" do
    assert :error == Sobelow.parse_remote_version("not a version")
    assert :error == Sobelow.parse_remote_version("")

    assert {:ok, %Version{major: 1, minor: 2, patch: 3}} =
             Sobelow.parse_remote_version(~c"1.2.3\n")
  end
end
