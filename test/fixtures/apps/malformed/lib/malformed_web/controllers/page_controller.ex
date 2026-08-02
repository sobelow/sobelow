defmodule MalformedWeb.PageController do
  use MalformedWeb, :controller

  def index(conn, %{"path" => path}) do
    send_file(conn, 200, path)
  end
end
