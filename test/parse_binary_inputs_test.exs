defmodule Sobelow.ParseBinaryInputsTest do
  use ExUnit.Case, async: true
  alias Sobelow.Parse

  for {expression, labels} <- [
        {"<<data::binary>>", [:data]},
        {"<<data::bytes, 1::8>>", [:data]},
        {"<<data::bitstring>>", [:data]},
        {"<<data::bits>>", [:data]},
        {"<<data::utf8, other::utf16-little, last::utf32-native>>", [:data, :other, :last]},
        {"<<1::size(length)-unit(8)>>", [:length]},
        {"<<data::binary-size(length)>>", [:data, :length]},
        {"[<<data::binary>>, <<1::8>>]", [:data]},
        {"<<conn.params[\"data\"]::binary>>", ["conn.params"]},
        {~S|~s"prefix#{data}"|, [:data]},
        {~S|~c"prefix#{data}"|, [:data]},
        {"<<1::8, 2::little-32>>", []},
        {"<<1::integer-unsigned-big-size(8)-unit(1)>>", []},
        {"<<1.0::float-64>>", []},
        {"<<-1::signed-8>>", []},
        {~S|<<"literal"::binary>>|, []},
        {~S|~S"literal"|, []},
        {~S|~C"literal"|, []},
        {~S|~s"literal"|, []},
        {~S|~c"literal"|, []},
        {~S|[~S"literal", ~c"literal"]|, []},
        {"[<<1::8>>, <<2::16>>]", []},
        {"<<>>", []},
        {"@compressed", ["dynamic value"]}
      ] do
    test "binary input labels for #{expression}" do
      ast = Code.string_to_quoted!(unquote(expression))
      assert Parse.binary_input_vars(ast) == unquote(labels)
    end
  end
end
