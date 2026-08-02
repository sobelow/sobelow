defmodule Sobelow.Mixfile do
  use Mix.Project

  @source_url "https://github.com/sobelow/sobelow"
  @version "0.14.1"

  def project do
    [
      app: :sobelow,
      version: @version,
      elixir: "~> 1.12",
      elixirc_paths: elixirc_paths(Mix.env()),
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      package: package(),
      description: "Security-focused static analysis for Elixir & the Phoenix framework",
      name: "Sobelow",
      homepage_url: "https://sobelow.io",
      docs: docs(),
      aliases: aliases(),
      escript: [main_module: Mix.Tasks.Sobelow]
    ]
  end

  # Replaces the `:preferred_cli_env` project key, deprecated in Elixir 1.19.
  # Older releases simply ignore this callback; CI sets MIX_ENV explicitly, so
  # nothing depends on it there.
  def cli do
    [
      preferred_envs: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.cobertura": :test
      ]
    ]
  end

  def application do
    [extra_applications: [:logger, :eex, :inets]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # "Prod" Dependencies
      {:jason, "~> 1.0"},

      # Dev / Test Dependencies
      {:ex_doc, "~> 0.37", only: :dev},
      {:credo, "~> 1.7.19", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18", only: :test}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      maintainers: ["Griffin Byatt", "Holden Oullette"],
      # `usage-rules.md` is not in Hex's default file list, but downstream projects
      # pull it into their agents' context, so it has to ship.
      files: ~w(lib mix.exs .formatter.exs README.md CHANGELOG.md LICENSE usage-rules.md),
      links: %{
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "GitHub" => @source_url
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url: @source_url,
      source_ref: "v#{@version}",
      extras: ["README.md", "usage-rules.md", "CHANGELOG.md"]
    ]
  end

  defp aliases do
    [
      "test.all": [
        "hex.audit",
        "format --check-formatted",
        "compile --warnings-as-errors",
        "deps.unlock --check-unused",
        "credo --all --strict"
      ]
    ]
  end
end
