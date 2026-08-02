import Config

# Heredoc value: the literal-source substitution used to pin down the exact line
# of the secret cannot match this, so the finding falls back to the `config` line.
config :secrets, :signing,
  signing_secret: """
  BQFsRdSCcQrTlLGYQKKiIZWaHPmMcBnGqjjnLDvzGwmXCLNaXcXqhLbj2XKlmJLQ
  """

# Escaped quote inside the value: also unmatchable by literal substitution.
config :secrets, :legacy, password: "hunter2 \"quoted\" tail"

# Plain literal spanning two lines: the secret's own line (16) is reported,
# not the line the `config` call starts on (15).
config :secrets, SecretsWeb.Endpoint,
  secret_key_base: "GYQKKiIZWaHPmMcBnGqjjnLDvzGwmXCLNaXcXqhLbj2XKlmJLQBOFsRdSCcQrTlL"
