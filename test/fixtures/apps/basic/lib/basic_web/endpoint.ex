defmodule BasicWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :basic

  socket("/socket", BasicWeb.UserSocket,
    websocket: [check_origin: false],
    longpoll: false
  )
end
