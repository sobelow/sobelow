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
    assert Sobelow.Utils.get_app_name("./test/fixtures/utils/mix_with_releases_test_app.exs") ==
             "test"
  end

  describe "Utils.imports?/2 and Utils.uses?/2" do
    defp meta_funs(source) do
      {:ok, ast} = Code.string_to_quoted(source)
      Sobelow.Parse.get_meta_funs(ast)
    end

    test "match a plain import" do
      %{import_funs: imports} = meta_funs("import Ecto.Adapters.SQL")

      assert Sobelow.Utils.imports?(imports, [:Ecto, :Adapters, :SQL])
    end

    test "match an import with options" do
      %{import_funs: imports} = meta_funs("import Ecto.Adapters.SQL, only: [query: 3]")

      assert Sobelow.Utils.imports?(imports, [:Ecto, :Adapters, :SQL])
    end

    test "match an import of a module that was aliased first" do
      %{import_funs: imports} = meta_funs("alias Ecto.Adapters.SQL\nimport SQL")

      assert Sobelow.Utils.imports?(imports, [:Ecto, :Adapters, :SQL])
    end

    test "do not match a different module with the same last segment" do
      %{import_funs: imports} = meta_funs("import Some.Other.SQL")

      refute Sobelow.Utils.imports?(imports, [:Ecto, :Adapters, :SQL])
    end

    test "do not match a longer name that merely contains the target" do
      %{import_funs: imports} = meta_funs("import My.Ecto.Adapters.SQL")

      refute Sobelow.Utils.imports?(imports, [:Ecto, :Adapters, :SQL])
    end

    test "uses?/2 matches a `use` with options" do
      %{use_funs: uses} = meta_funs("use Ecto.Repo, otp_app: :my_app")

      assert Sobelow.Utils.uses?(uses, [:Ecto, :Repo])
      refute Sobelow.Utils.uses?(uses, [:Ecto, :Adapters, :SQL])
    end

    test "an empty list matches nothing" do
      refute Sobelow.Utils.imports?([], [:Ecto, :Adapters, :SQL])
      refute Sobelow.Utils.uses?([], [:Ecto, :Repo])
    end
  end
end
