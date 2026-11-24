defmodule Sobelow.MetadataTest do
  use ExUnit.Case, async: false
  alias Sobelow.Parse
  alias Sobelow.Parse.Metadata

  setup do
    previous = Application.get_env(:sobelow, :skip)
    on_exit(fn -> Application.put_env(:sobelow, :skip, previous) end)
    :ok
  end

  test "only specs for the following name and arity carry earlier skips to the definition" do
    Application.put_env(:sobelow, :skip, true)

    for {spec, head, applies?} <- [
          {"read() :: term()", "read", true},
          {"read(binary()) :: term()", ~S/read(path, opts \\ [])/, true},
          {"read() :: term()", "read(path)", false},
          {"other(binary()) :: term()", "read(path)", false},
          {"unquote(generated_spec)", "read(path)", false}
        ] do
      ast =
        Code.string_to_quoted!("""
        @sobelow_skip ["Traversal.FileModule"]
        @spec #{spec}
        @deprecated "Use the new API"
        @sobelow_skip ["Misc.BinToTerm"]
        def #{head}, do: :ok
        """)

      {:__block__, _, statements} = ast
      key = Metadata.definition_key(List.last(statements))

      checks =
        if applies?, do: ["Traversal.FileModule", "Misc.BinToTerm"], else: ["Misc.BinToTerm"]

      assert Metadata.function_skips(ast) == %{key => checks}, spec
    end
  end

  test "combined metadata matches separate extraction for nested modules and skips" do
    sources = [
      "File.read(path)",
      "",
      """
      defmodule Parent do
        use Web, :controller
        @value 1
        @sobelow_skip ["Traversal.FileModule"]
        def read(path), do: File.read(path)
        defmodule Child do
          use Ecto.Repo
          import Ecto.Adapters.SQL
          @sobelow_skip ["Config.CSRF"]
          pipeline :browser do
            plug :accepts, ["html"]
          end
          def query(value), do: query(__MODULE__, value, [])
        end
      end
      defmodule Sibling do
        def read(path), do: File.read(path)
      end
      """,
      """
      defmodule FunctionBuilder do
        def build(path) do
          defmodule FunctionChild do
            def read(path), do: File.read(path)
          end
          File.read(path)
        end
      end
      """,
      """
      defmodule AttributeBuilder do
        @nested (defmodule AttributeChild do
          def read(path), do: File.read(path)
        end)
      end
      """,
      """
      defmodule Builder do
        @nested defmodule AttributeChild do
          def read(path), do: File.read(path)
        end
        def build(path) do
          defmodule FunctionChild do
            def read(path), do: File.read(path)
          end
          File.read(path)
        end
      end
      """,
      """
      defmodule module_name(use(Web, :controller)) do
        def read(path), do: File.read(path)
      end
      """
    ]

    for skip <- [true, false], source <- sources do
      Application.put_env(:sobelow, :skip, skip)
      ast = Code.string_to_quoted!(source)

      assert Parse.file_metadata(ast) ==
               {Parse.get_meta_funs(ast), Parse.get_module_meta_funs(ast)}
    end
  end
end
