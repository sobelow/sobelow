defmodule SobelowTest.Config.ConfigTest do
  use ExUnit.Case
  alias Sobelow.Config

  test "Extracts config" do
    config = "./test/fixtures/utils/config.exs"
    assert Config.get_configs(:security_option, config) != []
  end

  test "Handles nil config" do
    config = "./test/fixtures/utils/nil_config.exs"
    assert Config.get_configs(:security_option, config) == []
  end

  @tag :tmp_dir
  test "non-keyword endpoint config cannot satisfy a security setting", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "prod.exs")
    File.write!(path, "config :basic, BasicWeb.Endpoint, [\"https\"]\n")

    assert Config.get_app_configs(:https, path) == []
  end
end
