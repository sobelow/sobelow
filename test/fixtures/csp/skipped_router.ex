# Router has put_secure_browser_headers without CSP, but skipped
defmodule SkippedCSPRouter do
  @moduledoc false

  # sobelow_skip ["Config.CSP"]
  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:put_secure_browser_headers)
  end

  pipeline :other do
    plug(:accepts, ["html"])
    plug(:put_secure_browser_headers)
  end
end
