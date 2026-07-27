# Router is missing plug :protect_from_forgery, but skipped
defmodule SkippedCSRFRouter do
  @moduledoc false

  # sobelow_skip ["Config.CSRF"]
  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_flash)
  end

  pipeline :other do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    plug(:fetch_flash)
  end
end
