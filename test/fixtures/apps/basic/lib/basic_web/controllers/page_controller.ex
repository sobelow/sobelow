defmodule BasicWeb.PageController do
  use BasicWeb, :controller

  def index(conn, %{"path" => path}) do
    send_file(conn, 200, path)
  end

  def download(conn, %{"name" => name}) do
    File.read(name)
  end

  def search(conn, %{"term" => term}) do
    Ecto.Adapters.SQL.query(Repo, "SELECT * FROM users WHERE name = '#{term}'")
    conn
  end

  def ping(conn, %{"host" => host}) do
    System.cmd("ping", [host])
    conn
  end
end
