defmodule SobelowTest.DOS.XMLTest do
  use ExUnit.Case, async: true
  alias Sobelow.DOS.XML

  for call <- [
        ":xmerl_scan.string(data, allow_entities: true)",
        ":xmerl_scan.file(data, allow_entities: true)",
        "data |> :xmerl_scan.string(allow_entities: true)",
        ":xmerl_scan.string(data, allow_entities: false, allow_entities: true)",
        ":xmerl_sax_parser.stream(data, external_entities: :all)",
        ":xmerl_sax_parser.file(data, external_entities: :file)",
        ":xmerl_sax_parser.stream(data, entity_recurse_limit: 4)",
        ":xmerl_sax_parser.stream(data, entity_recurse_limit: 0, entity_recurse_limit: 9)",
        ":xmerl_sax_parser.stream(data, external_entities: :none, external_entities: :file)",
        ":xmerl_sax_parser.stream(data, [:skip_external_dtd, external_entities: :all])",
        ":xmerl_sax_parser.stream(data, [:disallow_entities, external_entities: :file])"
      ] do
    test "reports explicit option risk in #{call}" do
      ast = Code.string_to_quoted!("def parse(data), do: #{unquote(call)}")
      assert {[{_, [:data]}], [:data], {:parse, 1}} = XML.parse_def(ast)
    end
  end

  for call <- [
        ":xmerl_scan.string(data)",
        ":xmerl_scan.string(data, [])",
        ":xmerl_scan.string(data, opts)",
        ":xmerl_scan.string(data, allow_entities: value)",
        ":xmerl_scan.string(data, allow_entities: true, allow_entities: false)",
        ":xmerl_scan.string(data, allow_entities: true, allow_entities: value)",
        ":xmerl_scan.string(~c\"<root/>\", allow_entities: true)",
        ":xmerl_sax_parser.stream(data, [])",
        ":xmerl_sax_parser.stream(data, external_entities: :none)",
        ":xmerl_sax_parser.stream(data, external_entities: :all, external_entities: :none)",
        ":xmerl_sax_parser.stream(data, entity_recurse_limit: 3)",
        ":xmerl_sax_parser.stream(data, entity_recurse_limit: 9, entity_recurse_limit: 0)",
        ":xmerl_sax_parser.stream(data, entity_recurse_limit: -1)",
        ":xmerl_sax_parser.stream(data, [:disallow_entities, entity_recurse_limit: 9])",
        ":xmerl_sax_parser.stream(data, [:skip_external_dtd])",
        ":xmerl_sax_parser.stream(data, entity_recurse_limit: limit)",
        ":other.string(data, allow_entities: true)",
        "string(data, allow_entities: true)",
        ":xmerl_scan.string(data, [], extra)"
      ] do
    test "omits protected, default-only or unknown call #{call}" do
      ast = Code.string_to_quoted!("def parse(data), do: #{unquote(call)}")
      assert {[], _, _} = XML.parse_def(ast)
    end
  end

  test "bounded runtime example distinguishes entity rejection from unsupported protection" do
    xml = "<!DOCTYPE root [<!ENTITY item 'small'>]><root>&item;</root>"

    # apply keeps these optional runtime experiments independent of xmerl being
    # an application dependency. Older releases may reject protective options.
    if Code.ensure_loaded?(:xmerl_sax_parser) do
      assert {:ok, _, _} = sax_stream("<root/>", [])
      assert {:ok, _, _} = sax_stream(xml, [])

      case sax_stream("<root/>", [:disallow_entities]) do
        {:ok, _, _} ->
          assert {:fatal_error, _, ~c"Entities not allowed in document", _, _} =
                   sax_stream(xml, [:disallow_entities])

        result ->
          assert result == {:error, ~c"Option: disallow_entities not supported"}
          assert sax_stream(xml, [:disallow_entities]) == result
      end
    end
  end

  test "bounded runtime example verifies last duplicate recursion limit wins when supported" do
    # This chain expands to one character; it has no external references.
    xml = "<!DOCTYPE root [<!ENTITY a 'x'><!ENTITY b '&a;'><!ENTITY c '&b;'>]><root>&c;</root>"

    if Code.ensure_loaded?(:xmerl_sax_parser) do
      case sax_stream(xml, entity_recurse_limit: 9) do
        {:ok, _, _} ->
          assert {:fatal_error, _, ~c"Too deep", _, _} =
                   sax_stream(xml, entity_recurse_limit: 0)

          assert {:ok, _, _} =
                   sax_stream(xml, entity_recurse_limit: 0, entity_recurse_limit: 9)

          assert {:fatal_error, _, ~c"Too deep", _, _} =
                   sax_stream(xml, entity_recurse_limit: 9, entity_recurse_limit: 0)

        result ->
          assert result == {:error, ~c"Option: {entity_recurse_limit,9} not supported"}
      end
    end
  end

  defp sax_stream(xml, options), do: apply(:xmerl_sax_parser, :stream, [xml, options])
end
