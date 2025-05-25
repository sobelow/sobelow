defmodule Test.Mixfile do
  use Mix.Project

  def project do
    [
      app: :test,
      version: "0.1.0",
      releases: [
        test: [
          applications: [
            opentelemetry_exporter: :permanent,
            opentelemetry: :temporary
          ]
        ]
      ]
    ]
  end
end
