defmodule SecretsWeb.Router do
  use SecretsWeb, :router

  pipeline :api do
    plug(:accepts, ["json"])
  end
end
