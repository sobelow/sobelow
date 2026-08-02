import Config

# HTTPS is configured here but `force_ssl` is not set anywhere, so HSTS is off.
config :basic, BasicWeb.Endpoint,
  https: [
    port: 443,
    cipher_suite: :strong
  ]
