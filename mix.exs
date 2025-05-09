defmodule Sobelow.Mixfile do
  use Mix.Project

  @source_url "https://github.com/sobelow/sobelow"
  @version "0.14.0"

  def project do
    [
      app: :sobelow,
      version: @version,
      elixir: "~> 1.12",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.cobertura": :test
      ],
      package: package(),
      description: "Security-focused static analysis for Elixir & the Phoenix framework",
      name: "Sobelow",
      homepage_url: "https://sobelow.io",
      docs: docs(),
      aliases: aliases(),
      escript: [main_module: Mix.Tasks.Sobelow]
    ]
  end

  def application do
    [extra_applications: [:logger, :eex, :inets]]
  end

  defp deps do
    [
      # "Prod" Dependencies
      {:jason, "~> 1.0"},

      # Dev / Test Dependencies
      {:ex_doc, "~> 0.37", only: :dev},
      {:credo, "~> 1.7.12", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.18", only: :test}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      maintainers: ["Griffin Byatt", "Holden Oullette"],
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
      extras: ["README.md", "CHANGELOG.md"]
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
