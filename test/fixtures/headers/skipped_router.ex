# Router is missing plug :put_secure_browser_headers, but skipped
defmodule SkippedHeadersRouter do
  @moduledoc false

  # sobelow_skip ["Config.Headers"]
  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:protect_from_forgery)
  end

  pipeline :other do
    plug(:accepts, ["html"])
    plug(:protect_from_forgery)
  end
end
