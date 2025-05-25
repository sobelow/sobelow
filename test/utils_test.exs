defmodule SobelowTest.UtilsTest do
  use ExUnit.Case

  test "Utils.get_app_name/1 understands module attributes" do
    assert Sobelow.Utils.get_app_name("./test/fixtures/utils/mix.exs") == "foo_bar"
  end

  test "Utils.get_app_name/1 handles releases config correctly for app named :app" do
    assert Sobelow.Utils.get_app_name("./test/fixtures/utils/mix_with_releases.exs") == "app"
  end

  test "Utils.get_app_name/1 handles releases config correctly for app named :my_app" do
    assert Sobelow.Utils.get_app_name("./test/fixtures/utils/mix_with_releases_my_app.exs") ==
             "my_app"
  end

  test "Utils.get_app_name/1 handles releases config correctly for app named :test" do
    assert Sobelow.Utils.get_app_name("./test/fixtures/utils/mix_with_releases_test.exs") ==
             "test"
  end
end
