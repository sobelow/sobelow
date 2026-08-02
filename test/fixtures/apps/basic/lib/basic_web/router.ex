defmodule BasicWeb.Router do
  use BasicWeb, :router

  # Missing `protect_from_forgery` and `put_secure_browser_headers`.
  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
  end

  scope "/", BasicWeb do
    pipe_through(:browser)

    get("/", PageController, :index)
  end
end
