defmodule SobelowTest.Config.CSWHTest do
  use ExUnit.Case
  alias Sobelow.Parse
  alias Sobelow.Config.CSWH

  test "checks normal endpoint" do
    endpoint = "./test/fixtures/cswh/good_endpoint.ex"

    vuln? =
      Parse.ast(endpoint)
      |> Parse.get_funs_of_type(:socket)
      |> Enum.any?(fn socket ->
        case CSWH.check_socket(socket) do
          {true, _} -> true
          _ -> false
        end
      end)

    refute vuln?
  end

  test "checks normal endpoint with configuration" do
    endpoint = "./test/fixtures/cswh/good_endpoint_2.ex"

    vuln? =
      Parse.ast(endpoint)
      |> Parse.get_funs_of_type(:socket)
      |> Enum.any?(fn socket ->
        case CSWH.check_socket(socket) do
          {true, _} -> true
          _ -> false
        end
      end)

    refute vuln?
  end

  test "checks no-check endpoint" do
    endpoint = "./test/fixtures/cswh/bad_endpoint.ex"

    vuln? =
      Parse.ast(endpoint)
      |> Parse.get_funs_of_type(:socket)
      |> Enum.any?(fn socket ->
        case CSWH.check_socket(socket) do
          {true, :high} -> true
          _ -> false
        end
      end)

    assert vuln?
  end

  test "an explicit origin allowlist is accepted" do
    endpoint = "./test/fixtures/cswh/soso_endpoint.ex"

    vuln? =
      Parse.ast(endpoint)
      |> Parse.get_funs_of_type(:socket)
      |> Enum.any?(fn socket ->
        case CSWH.check_socket(socket) do
          {true, :low} -> true
          _ -> false
        end
      end)

    refute vuln?
  end

  test "check_origin: :conn validates the request host" do
    refute CSWH.check_socket(socket("websocket: [check_origin: :conn]")) |> elem(0)
  end

  test "CSRF validation lowers confidence when origin checks are disabled" do
    assert {true, :low} =
             CSWH.check_socket(socket("websocket: [check_origin: false, check_csrf: true]"))
  end

  defp socket(options) do
    Code.string_to_quoted!("socket \"/socket\", UserSocket, #{options}")
  end
end
