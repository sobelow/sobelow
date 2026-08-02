defmodule Sobelow.NoRouterTest do
  @moduledoc """
  Coverage for scanning a project that has no Phoenix router.

  Sobelow warns when it cannot find a router, which is noise for a project that
  legitimately has none. `--no-router` (and the `:none` router value it is
  shorthand for) suppresses it.

  Both fixture layouts matter: a `web/` directory makes Sobelow treat a project
  as pre-Phoenix 1.3, which resolves the router through a different code path.
  """
  use Sobelow.ScanCase

  @warning "cannot find the router"

  defp warned?(fixture, opts) do
    {_stdout, stderr} = scan_io(fixture, opts)
    stderr =~ @warning
  end

  for fixture <- ["no_router", "no_router_legacy"] do
    describe "#{fixture}" do
      test "warns by default" do
        assert warned?(unquote(fixture), [])
      end

      test "--router :none suppresses the warning" do
        refute warned?(unquote(fixture), router: ":none")
      end

      # A `.sobelow-conf` holds a real atom rather than the string the CLI
      # produces. This used to raise from `Path.expand/1` on the `web/` layout.
      test "a :none atom from a config file suppresses the warning" do
        refute warned?(unquote(fixture), router: :none)
      end

      test "an explicit nil router still warns" do
        assert warned?(unquote(fixture), router: nil)
      end

      test "the scan still completes and reports findings normally" do
        report = scan(unquote(fixture), router: ":none", format: "json")

        assert Map.has_key?(report, "findings")
      end
    end
  end
end
