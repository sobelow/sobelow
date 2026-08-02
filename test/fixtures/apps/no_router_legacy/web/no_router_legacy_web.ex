# The presence of a `web/` directory is what makes Sobelow treat a project as
# pre-Phoenix 1.3, which selects a different router-resolution path. There is
# still no router here.
defmodule NoRouterLegacyWeb do
  def hello, do: :world
end
