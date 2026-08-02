defmodule MalformedWeb.Router do
  use MalformedWeb, :router

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
  end
end
