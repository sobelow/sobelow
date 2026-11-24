defmodule SobelowTest.E2E.BinToTermTest do
  use Sobelow.ScanCase, async: false

  test "grades decoder protections and preserves historical Erlang fingerprints" do
    temp_fixture_file("basic", "lib/term_decoder.ex", """
    defmodule TermDecoder do
      def plain(data), do: :erlang.binary_to_term(data)
      def safe(data), do: :erlang.binary_to_term(data, [:safe])
      def piped(data), do: data |> :erlang.binary_to_term([:used, :safe])
      def unknown(data, opts), do: :erlang.binary_to_term(data, opts)
      def executable(data), do: Plug.Crypto.non_executable_binary_to_term(data)
      def protected(data), do: Plug.Crypto.non_executable_binary_to_term(data, [:safe])
      def protected_pipe(data), do: data |> Plug.Crypto.non_executable_binary_to_term([:safe, :used])
      def unknown_plug(data, opts), do: Plug.Crypto.non_executable_binary_to_term(data, opts)
      def no_safe(data), do: Plug.Crypto.non_executable_binary_to_term(data, [:used])
    end
    """)

    found = scan("basic") |> findings_for("Misc.BinToTerm")
    assert Enum.frequencies_by(found, & &1["confidence"]) == %{"high" => 5, "medium" => 2}
    assert Enum.sort(Enum.map(found, & &1["line"])) == [2, 3, 4, 5, 6, 9, 10]

    Sobelow.FindingLog.log()
    |> Map.values()
    |> List.flatten()
    |> Enum.each(fn {_details, finding, _} ->
      if finding.type == "Misc.BinToTerm: Unsafe `binary_to_term`" and
           finding.vuln_line_no in 2..5 do
        historical =
          Sobelow.Parse.get_erlang_fun_vars_and_meta(
            finding.fun_source,
            0,
            :binary_to_term,
            :erlang
          )

        [old] =
          Sobelow.Finding.init(finding.type, finding.filename, :high)
          |> Sobelow.Finding.multi_from_def(finding.fun_source, historical)

        assert Sobelow.Finding.fingerprint(old) == Sobelow.Finding.fingerprint(finding)

        assert Sobelow.Finding.legacy_fingerprint(old) ==
                 Sobelow.Finding.legacy_fingerprint(finding)
      end
    end)
  end

  test "resolves Plug aliases and imports while retaining safe pipe suppression" do
    temp_fixture_file("basic", "lib/term_decoder.ex", """
    defmodule TermDecoder do
      alias Plug.Crypto, as: Crypto
      import Plug.Crypto, only: [non_executable_binary_to_term: 2]
      def unsafe(data), do: Crypto.non_executable_binary_to_term(data)
      def imported(data), do: non_executable_binary_to_term(data, [])
      def pipe(data), do: data |> non_executable_binary_to_term([:safe])
      def alias_pipe(data), do: data |> Crypto.non_executable_binary_to_term([:safe])
      def unrelated(data), do: Other.non_executable_binary_to_term(data)
    end
    """)

    found = scan("basic") |> findings_for("Misc.BinToTerm")
    assert Enum.sort(Enum.map(found, & &1["line"])) == [4, 5]
    assert [] = scan("basic", ignored: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
  end

  test "confidence threshold, skips and SARIF retain their normal behavior" do
    temp_fixture_file("basic", "lib/term_decoder.ex", """
    defmodule TermDecoder do
      # sobelow_skip ["Misc.BinToTerm"]
      def skipped(data), do: Plug.Crypto.non_executable_binary_to_term(data)
      def safe(data), do: :erlang.binary_to_term(data, [:safe])
    end
    """)

    assert [%{"confidence" => "medium"}] =
             scan("basic", skip: true) |> findings_for("Misc.BinToTerm")

    assert [] = scan("basic", skip: true, threshold: :high) |> findings_for("Misc.BinToTerm")
    {output, _} = scan_io("basic", skip: true, format: "sarif")
    [run] = Jason.decode!(output)["runs"]
    assert Enum.count(run["results"], &(&1["ruleId"] == "SBLW014")) == 1

    rule = Enum.find(run["tool"]["driver"]["rules"], &(&1["id"] == "SBLW014"))
    assert rule["help"]["text"] =~ "ETF supports compressed terms"
    assert rule["help"]["markdown"] =~ "validation after decoding"
  end

  test "request-controlled ETF map crossing to consumers versus checked scalar" do
    temp_fixture_file("basic", "lib/term_decoder.ex", """
    defmodule TermDecoder do
      def parser(conn) do
        raw = conn.params["cursor"]
        {:ok, binary} = Base.decode64(raw)
        term = Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
        if is_map(term), do: {:ok, term}, else: {:error, :invalid}
      end

      def forward(conn) do
        term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
        case term do
          %{ "position" => pos} when is_integer(pos) -> Consumer.consume(term)
          _ -> :invalid
        end
      end

      def scalar(conn) do
        term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
        case term do
          %{"position" => pos} when is_integer(pos) -> Consumer.consume(pos)
          _ -> {:error, :invalid}
        end
      end
    end
    """)

    found = scan("basic") |> findings_for("Misc.BinToTerm")
    assert Enum.sort(Enum.map(found, & &1["line"])) == [5, 10]
    assert Enum.all?(found, &(&1["confidence"] == "high"))
    assert Enum.all?(found, &(&1["variable"] =~ "unchecked handoff at line"))
  end

  test "literal safe decoders in wrappers, pipes and aliases use resolved calls" do
    temp_fixture_file("basic", "lib/term_decoder.ex", """
    defmodule TermDecoder do
      alias Plug.Crypto, as: Crypto
      import Plug.Crypto, only: [non_executable_binary_to_term: 2]
      defp decode(raw), do: {:ok, Crypto.non_executable_binary_to_term(raw, [:safe])}

      def direct(conn) do
        {:ok, binary} = Base.decode64(conn.params["cursor"])
        {:ok, term} = decode(binary)
        Consumer.consume(term)
      end

      def imported(conn) do
        term = conn.params["cursor"] |> non_executable_binary_to_term([:safe])
        Consumer.consume(term)
      end

      def unrelated(conn) do
        term = Other.non_executable_binary_to_term(conn.params["cursor"], [:safe])
        Consumer.consume(term)
      end
    end
    """)

    found = scan("basic") |> findings_for("Misc.BinToTerm")
    assert Enum.sort(Enum.map(found, & &1["line"])) == [4, 13]
    assert Enum.all?(found, &(&1["confidence"] == "high"))
  end

  test "read_body with-branches and rejected-term inspection" do
    temp_fixture_file("basic", "lib/term_decoder.ex", """
    defmodule TermDecoder do
      def read(conn) do
        with {:ok, body, conn} <- Plug.Conn.read_body(conn),
             {:ok, binary} <- Base.decode64(body),
             term = Plug.Crypto.non_executable_binary_to_term(binary, [:safe]) do
          {:ok, term}
        else
          _ -> {:error, :invalid}
        end
      end

      def inspect_rejection(conn) do
        term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
        case term do
          %{"position" => pos} when is_integer(pos) -> {:ok, pos}
          rejected -> inspect(rejected)
        end
      end

      def reject_fixed(conn) do
        term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
        case term do
          %{"position" => pos} when is_integer(pos) -> {:ok, pos}
          _ -> {:error, :invalid}
        end
      end
    end
    """)

    found = scan("basic") |> findings_for("Misc.BinToTerm")
    assert Enum.sort(Enum.map(found, & &1["line"])) == [5, 13]
    assert Enum.any?(found, &(&1["variable"] =~ "line 16"))
  end

  test "assignment expressions keep nested branches and their handoffs" do
    path =
      temp_fixture_file("basic", "lib/term_flow.ex", """
      defmodule TermFlow do
        def nested(conn) do
          result = if conn.params["enabled"] do
            value = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
            case value do
              %{"position" => pos} when is_integer(pos) -> Consumer.consume(pos)
              _ -> Consumer.consume(value)
            end
          else
            :disabled
          end
          result
        end

        def scrutinee(conn) do
          case value = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe]) do
            _ -> :ignored
          end
          Consumer.consume(value)
        end

        def condition(conn) do
          if value = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe]) do
            :ignored
          end
          Consumer.consume(value)
        end

        def scoped(conn) do
          value = :fixed
          if conn.params["enabled"] do
            value = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
            Consumer.consume(value)
          end
          Consumer.consume(value)
        end
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")

    assert found
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(& &1["line"])
           |> Enum.sort() ==
             [4, 16, 23, 32]
  end

  test "with failures, guards, and irrefutable patterns distinguish returns" do
    path =
      temp_fixture_file("basic", "lib/term_with.ex", """
      defmodule TermWith do
        def unchecked(conn) do
          with {:ok, value} <- Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe]),
               do: :accepted
        end

        def rejected(conn) do
          with {:ok, value} <- Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe]),
               do: :accepted,
               else: (_ -> :invalid)
        end

        def irrefutable(conn) do
          with value <- Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe]),
               do: :accepted
        end

        def inspected(conn) do
          with {:ok, value} <- Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe]),
               do: :accepted,
               else: (rejected -> inspect(rejected))
        end
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")

    assert found
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(& &1["line"])
           |> Enum.sort() ==
             [3, 19]
  end

  test "map field extraction is distinct from forwarding decoded map or an update" do
    path =
      temp_fixture_file("basic", "lib/term_maps.ex", """
      defmodule TermMaps do
        def scalar(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          value = %{"position" => term}
          if is_integer(value["position"]), do: Consumer.consume(value["position"]), else: :invalid
        end

        def forwarded(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          value = %{"position" => term}
          if is_integer(value["position"]), do: Consumer.consume(value), else: :invalid
        end

        def updated(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          value = %{"position" => term}
          updated = %{value | other: :fixed}
          Consumer.consume(updated)
        end

        def request_params(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          %{conn | params: term}
        end
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")

    assert found
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(& &1["line"])
           |> Enum.sort() ==
             [9, 15, 22]
  end

  test "map updates drop overwritten fields but retain forwarded originals" do
    path =
      temp_fixture_file("basic", "lib/term_replacements.ex", """
      defmodule TermReplacements do
        def replaced(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          map = %{position: term}
          Consumer.consume(%{map | position: :fixed})
        end

        def retained(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          map = %{position: term, other: :fixed}
          Consumer.consume(%{map | other: :changed})
        end

        def nested(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          map = %{position: term, other: :fixed}
          updated = %{map | position: :fixed}
          Consumer.consume(%{updated | other: :changed})
        end

        def original(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          Consumer.consume(%{term | position: :fixed})
        end
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")

    assert found
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(& &1["line"])
           |> Enum.sort() == [9, 22]
  end

  test "bare piped local wrappers and scalar extractors resolve in their module" do
    path =
      temp_fixture_file("basic", "lib/term_pipes.ex", """
      defmodule TermPipes do
        defp decode(raw), do: Plug.Crypto.non_executable_binary_to_term(raw, [:safe])
        defp position(%{"position" => pos}) when is_integer(pos), do: pos
        defp position(_), do: :invalid

        def direct(conn), do: conn.params["cursor"] |> decode |> Consumer.consume()

        def checked_scalar(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          term |> position |> Consumer.consume()
        end
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")

    assert [%{"line" => 2, "confidence" => "high"}] =
             Enum.filter(found, &String.ends_with?(&1["file"], path))
  end

  test "function-head extractors require every clause to guard a scalar or reject" do
    path =
      temp_fixture_file("basic", "lib/term_extractors.ex", """
      defmodule TermExtractors do
        defp position(%{"position" => pos}) when is_integer(pos), do: {:ok, pos}
        defp position(_), do: {:error, :invalid}

        defp unguarded(%{"position" => pos}), do: pos
        defp unguarded(_), do: :invalid

        def scalar(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          Consumer.consume(position(term))
        end

        def unchecked(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          Consumer.consume(unguarded(term))
        end

        def original(conn) do
          term = Plug.Crypto.non_executable_binary_to_term(conn.params["cursor"], [:safe])
          position(term)
          Consumer.consume(term)
        end
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")

    assert found
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(& &1["line"])
           |> Enum.sort() ==
             [14, 19]
  end

  test "protocol and implementation scopes do not lend wrappers to sibling modules" do
    path =
      temp_fixture_file("basic", "lib/term_protocols.ex", """
      defmodule TermOuter do
        defp decode(raw), do: Plug.Crypto.non_executable_binary_to_term(raw, [:safe])
      end

      defprotocol TermProtocol do
        def consume(value)
      end

      defimpl TermProtocol, for: Map do
        defp decode(raw), do: Plug.Crypto.non_executable_binary_to_term(raw, [:safe])
        def run(conn), do: Consumer.consume(decode(conn.params["cursor"]))
      end

      defimpl TermProtocol, for: List do
        def run(conn), do: Consumer.consume(decode(conn.params["cursor"]))
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")

    assert found |> Enum.filter(&String.ends_with?(&1["file"], path)) |> Enum.map(& &1["line"]) ==
             [10]
  end

  test "multiple callers share one decoder finding, threshold, and saved skip" do
    path =
      temp_fixture_file("basic", "lib/term_handoffs.ex", """
      defmodule TermHandoffs do
        defp decode(data), do: Plug.Crypto.non_executable_binary_to_term(data, [:safe])
        def first(conn), do: Consumer.consume(decode(conn.params["cursor"]))
        def second(conn), do: Consumer.consume(decode(conn.params["cursor"]))
      end
      """)

    found =
      scan("basic", only: ["Misc.BinToTerm"], threshold: :high)
      |> findings_for("Misc.BinToTerm")
      |> Enum.filter(&String.ends_with?(&1["file"], path))

    assert [%{"line" => 2, "confidence" => "high"}] = found

    {output, _stderr} = scan_io("basic", only: ["Misc.BinToTerm"], format: "sarif")
    [run] = Jason.decode!(output)["runs"]

    results = Enum.filter(run["results"], &(&1["ruleId"] == "SBLW014"))
    assert [result] = results

    assert get_in(result, ["locations", Access.at(0), "physicalLocation", "region", "startLine"]) ==
             2

    skip_file = Path.join(fixture_path("basic"), ".sobelow-skips")
    original = File.read(skip_file)

    on_exit(fn ->
      case original do
        {:ok, contents} -> File.write!(skip_file, contents)
        {:error, :enoent} -> File.rm_rf!(skip_file)
      end
    end)

    scan_io("basic", only: ["Misc.BinToTerm"], mark_skip_all: true)
    assert File.read!(skip_file) =~ result["partialFingerprints"]["primaryLocationLineHash"]

    assert [] =
             scan("basic", only: ["Misc.BinToTerm"], skip: true) |> findings_for("Misc.BinToTerm")
  end

  test "wrapper skips do not suppress an unskipped caller, and caller skips only suppress themselves" do
    path =
      temp_fixture_file("basic", "lib/term_handoffs.ex", """
      defmodule TermHandoffs do
        # sobelow_skip ["Misc.BinToTerm"]
        defp decode(data), do: Plug.Crypto.non_executable_binary_to_term(data, [:safe])
        # sobelow_skip ["Misc.BinToTerm"]
        def first(conn), do: Consumer.consume(decode(conn.params["cursor"]))
        def second(conn), do: Consumer.consume(decode(conn.params["cursor"]))
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"], skip: true) |> findings_for("Misc.BinToTerm")
    assert [%{"line" => 3}] = Enum.filter(found, &String.ends_with?(&1["file"], path))
  end

  test "resolver token handoff through URL decoding and one local decoder wrapper" do
    path =
      temp_fixture_file("basic", "lib/page_token_resolver.ex", """
      defmodule PageTokenResolver do
        defp decode_token(binary),
          do: {:ok, Plug.Crypto.non_executable_binary_to_term(binary, [:safe])}

        def page(_source, args, %{context: %{actor: _actor}}) do
          with {:ok, binary} <- Base.url_decode64(args[:page_token], padding: false),
               {:ok, value} <- decode_token(binary),
               true <- match?({:page, %Date{}, offset} when is_integer(offset), value) do
            {:ok, value}
          else
            _ -> {:error, :invalid_token}
          end
        end

        def forward(_source, args, %{context: _context}) do
          {:ok, binary} = Base.url_decode64(args[:page_token])
          {:ok, value} = decode_token(binary)
          Consumer.consume(value)
        end

        def checked(_source, args, %{context: _context}) do
          {:ok, binary} = Base.url_decode64(args[:page_token])
          {:ok, value} = decode_token(binary)
          case value do
            %{"offset" => offset} when is_integer(offset) -> Consumer.consume(offset)
            _ -> {:error, :invalid_token}
          end
        end

        def matched_scalar(_source, args, %{context: _context}) do
          {:ok, binary} = Base.url_decode64(args[:page_token])
          value = Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
          if match?(%{"offset" => offset} when is_integer(offset), value),
            do: :accepted,
            else: {:error, :invalid_token}
        end

        def unknown_source(binary), do: Consumer.consume(decode_token(binary))
        def not_resolver(_source, args, _context),
          do: Consumer.consume(decode_token(args[:page_token]))
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")

    assert [%{"line" => 3, "confidence" => "high"}] =
             Enum.filter(found, &String.ends_with?(&1["file"], path))
  end

  test "URL decoder variants preserve request provenance for direct decoders" do
    path =
      temp_fixture_file("basic", "lib/url_terms.ex", """
      defmodule UrlTerms do
        def url_bang(_parent, args, %{context: _context}) do
          binary = Base.url_decode64!(args[:after], padding: false)
          term = Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
          Consumer.consume(term)
        end

        def plain_bang(_parent, args, %{context: _context}) do
          binary = Base.decode64!(args[:after])
          term = Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
          Consumer.consume(term)
        end
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")

    assert found
           |> Enum.filter(&String.ends_with?(&1["file"], path))
           |> Enum.map(& &1["line"])
           |> Enum.sort() == [4, 10]
  end

  test "parser handoff through literal decoder selection and multiple clauses" do
    decoder =
      temp_fixture_file("basic", "lib/format_decoder.ex", """
      defmodule FormatDecoder do
        def decode(""), do: {:ok, nil}
        def decode(<<131, 80, _rest::binary>>), do: {:error, :compressed}
        def decode(binary) do
          term = Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
          {:ok, term}
        rescue
          ArgumentError -> {:error, :invalid}
        end
      end
      """)

    parser =
      temp_fixture_file("basic", "lib/format_parser.ex", """
      defmodule FormatParser do
        alias Plug.Conn
        def parse(%Conn{} = conn, "application", "vnd.hex+" <> format, _headers, opts) do
          decoder = get_decoder(format, opts)
          conn |> Conn.read_body(opts) |> decode(decoder)
        end
        defp get_decoder(format, opts) do
          case format do
            "erlang" -> FormatDecoder
            "json" -> Keyword.fetch!(opts, :json_decoder)
          end
        end
        defp decode({:error, _}, _decoder), do: :error
        defp decode({:ok, body, conn}, decoder) do
          case decoder.decode(body) do
            {:ok, terms} when is_map(terms) -> {:ok, terms, conn}
            {:ok, terms} -> {:ok, %{"_json" => terms}, conn}
            {:error, _} -> :error
          end
        end
      end
      """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
    assert [%{"line" => 5, "confidence" => "high", "file" => ^decoder}] = found
    assert found |> hd() |> Map.fetch!("variable") =~ "unchecked handoff"
    refute Enum.any?(found, &(&1["file"] == parser))
  end

  test "checked scalar parser result does not forward the decoded aggregate" do
    decoder =
      temp_fixture_file("basic", "lib/format_decoder.ex", """
      defmodule FormatDecoder do
        def decode(binary), do: {:ok, Plug.Crypto.non_executable_binary_to_term(binary, [:safe])}
      end
      """)

    temp_fixture_file("basic", "lib/format_parser.ex", """
    defmodule FormatParser do
      alias Plug.Conn
      def parse(%Conn{} = conn, _type, _format, _headers, opts) do
        {:ok, body, _conn} = Conn.read_body(conn, opts)
        {:ok, term} = FormatDecoder.decode(body)
        case term do
          %{"position" => position} when is_integer(position) -> {:ok, position}
          _ -> {:error, :invalid}
        end
      end
    end
    """)

    assert [] =
             scan("basic", only: ["Misc.BinToTerm"])
             |> findings_for("Misc.BinToTerm")
             |> Enum.filter(&(&1["file"] == decoder))
  end

  test "cross-file alias dispatch follows the literal module and preserves decoder origin" do
    decoder =
      temp_fixture_file("basic", "lib/term_decoders.ex", """
      defmodule TermDecoders.Erlang do
        def decode(binary) do
          value = Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
          {:ok, value}
        end
      end

      defmodule TermDecoders.JSON do
        def decode(_binary), do: {:ok, %{}}
      end
      """)

    temp_fixture_file("basic", "lib/term_router.ex", """
    defmodule TermRouter do
      alias TermDecoders.Erlang, as: ErlangDecoder
      defp decoder(format) do
        case format do
          "erlang" -> ErlangDecoder
          "json" -> TermDecoders.JSON
        end
      end

      def parse(conn, format) do
        {:ok, binary, _conn} = Plug.Conn.read_body(conn)
        module = decoder(format)
        {:ok, value} = module.decode(binary)
        Consumer.consume(value)
      end
    end
    """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
    assert [%{"file" => ^decoder, "line" => 3, "confidence" => "high"}] = found

    {output, _} = scan_io("basic", only: ["Misc.BinToTerm"], format: "sarif")
    [run] = Jason.decode!(output)["runs"]
    assert Enum.count(run["results"], &(&1["ruleId"] == "SBLW014")) == 1
  end

  test "literal receiver choices beyond the dispatch bound warn without guessing" do
    decoders =
      Enum.map_join(1..13, "\n", fn index ->
        "defmodule TermChoice#{index} do\n  def decode(raw), do: Plug.Crypto.non_executable_binary_to_term(raw, [:safe])\nend"
      end)

    temp_fixture_file("basic", "lib/term_choices.ex", decoders)

    choices =
      Enum.map_join(1..11, "\n", fn index ->
        "#{index} -> TermChoice#{index}"
      end)

    parser =
      temp_fixture_file("basic", "lib/term_choice_parser.ex", """
      defmodule TermChoiceParser do
        defp choose(index, flag) do
          case index do
            #{choices}
            12 -> if flag, do: TermChoice12, else: TermChoice13
          end
        end

        def parse(conn, index, flag) do
          module = choose(index, flag)
          Consumer.consume(module.decode(conn.params["cursor"]))
        end
      end
      """)

    {stdout, stderr} = scan_io("basic", only: ["Misc.BinToTerm"])
    assert stderr =~ Path.basename(parser)
    assert stderr =~ "alternative limit"
    assert [] = Jason.decode!(stdout) |> findings_for("Misc.BinToTerm")
  end

  test "literal default arguments and private cross-file helpers are treated conservatively" do
    decoder =
      temp_fixture_file("basic", "lib/term_defaults.ex", """
      defmodule TermDefaults do
        def decode(binary, opts \\\\ []), do: Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
        defp private_decode(binary), do: Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
      end
      """)

    temp_fixture_file("basic", "lib/term_default_parser.ex", """
    defmodule TermDefaultParser do
      def parse(conn) do
        {:ok, binary, _conn} = Plug.Conn.read_body(conn)
        Consumer.consume(TermDefaults.decode(binary))
        Consumer.consume(TermDefaults.private_decode(binary))
      end
    end
    """)

    found = scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
    assert [%{"file" => ^decoder, "line" => 2}] = found
  end

  test "declaration-only defaults route through every implementation clause" do
    decoder =
      temp_fixture_file("basic", "lib/term_declared.ex", """
      defmodule TermDeclared do
        def decode(binary, options \\\\ [])
        def decode(binary, _options) when is_binary(binary),
          do: Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
        def decode(_, _options), do: :invalid
      end
      """)

    temp_fixture_file("basic", "lib/term_declaration_parser.ex", """
    defmodule TermDeclarationParser do
      def parse(conn) do
        {:ok, body, _conn} = Plug.Conn.read_body(conn)
        Consumer.consume(TermDeclared.decode(body))
      end
    end
    """)

    assert [%{"file" => ^decoder, "line" => 4, "confidence" => "high"}] =
             scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
  end

  test "cross-file skips apply to callers independently of decoder definitions" do
    decoder =
      temp_fixture_file("basic", "lib/term_skip_decoder.ex", """
      defmodule TermSkipDecoder do
        # sobelow_skip ["Misc.BinToTerm"]
        def decode(binary), do: Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
      end
      """)

    temp_fixture_file("basic", "lib/term_skip_parser.ex", """
    defmodule TermSkipParser do
      # sobelow_skip ["Misc.BinToTerm"]
      def ignored(conn), do: Consumer.consume(TermSkipDecoder.decode(conn.params["cursor"]))
      def reported(conn), do: Consumer.consume(TermSkipDecoder.decode(conn.params["cursor"]))
    end
    """)

    assert [%{"file" => ^decoder, "line" => 3, "confidence" => "high"}] =
             scan("basic", only: ["Misc.BinToTerm"], skip: true)
             |> findings_for("Misc.BinToTerm")
  end

  test "function annotations preserve ETF caller and decoder skips" do
    decoder =
      temp_fixture_file("basic", "lib/annotated_term_decoder.ex", """
      defmodule AnnotatedTermDecoder do
        # sobelow_skip ["Misc.BinToTerm"]
        @doc false
        @spec decode(binary()) :: term()
        def decode(binary), do: Plug.Crypto.non_executable_binary_to_term(binary, [:safe])
      end
      """)

    temp_fixture_file("basic", "lib/annotated_term_parser.ex", """
    defmodule AnnotatedTermParser do
      # sobelow_skip ["Misc.BinToTerm"]
      @impl false
      def ignored(conn), do: Consumer.consume(AnnotatedTermDecoder.decode(conn.params["cursor"]))
      def reported(conn), do: Consumer.consume(AnnotatedTermDecoder.decode(conn.params["cursor"]))
    end
    """)

    assert [%{"file" => ^decoder, "line" => 5}] =
             scan("basic", only: ["Misc.BinToTerm"], skip: true)
             |> findings_for("Misc.BinToTerm")
  end

  test "cross-file scalar validation rejects unforwarded terms" do
    decoder =
      temp_fixture_file("basic", "lib/term_validated_decoder.ex", """
      defmodule TermValidatedDecoder do
        def decode(raw), do: Plug.Crypto.non_executable_binary_to_term(raw, [:safe])
      end
      """)

    temp_fixture_file("basic", "lib/term_validated_parser.ex", """
    defmodule TermValidatedParser do
      defp position(%{"position" => value}) when is_integer(value), do: value
      defp position(_), do: :invalid

      def parse(conn) do
        term = TermValidatedDecoder.decode(conn.params["cursor"])
        Consumer.consume(position(term))
      end
    end
    """)

    assert [] =
             scan("basic", only: ["Misc.BinToTerm"])
             |> findings_for("Misc.BinToTerm")
             |> Enum.filter(&(&1["file"] == decoder))
  end

  test "findings are format independent and dynamic dispatch is not guessed" do
    decoder =
      temp_fixture_file("basic", "lib/term_format_decoder.ex", """
      defmodule TermFormatDecoder do
        def decode(raw), do: Plug.Crypto.non_executable_binary_to_term(raw, [:safe])
      end
      """)

    temp_fixture_file("basic", "lib/term_format_parser.ex", """
    defmodule TermFormatParser do
      def literal(conn), do: Consumer.consume(TermFormatDecoder.decode(conn.params["cursor"]))
      def dynamic(conn, module), do: Consumer.consume(module.decode(conn.params["cursor"]))
    end
    """)

    for format <- ["json", "quiet", "github", "txt", "sarif"] do
      {output, _} = scan_io("basic", only: ["Misc.BinToTerm"], format: format)
      log = Sobelow.FindingLog.log() |> Map.values() |> List.flatten()

      assert [{_details, finding, _meta}] =
               Enum.filter(log, fn {_details, finding, _meta} ->
                 finding.type == "Misc.BinToTerm: Unsafe `binary_to_term`" and
                   finding.filename == decoder
               end)

      assert finding.vuln_line_no == 2
      assert output != ""
    end
  end

  test "guards on encoded request fields do not validate decoded terms" do
    decoder =
      temp_fixture_file("basic", "lib/guarded_request_decoder.ex", """
      defmodule GuardedRequestDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      """)

    temp_fixture_file("basic", "lib/guarded_request_parser.ex", """
    defmodule GuardedRequestParser do
      def parse(conn) do
        if is_binary(conn.params["cursor"]) do
          Consumer.consume(GuardedRequestDecoder.decode(conn.params["cursor"]))
        end
      end
    end
    """)

    assert [%{"file" => ^decoder, "line" => 2, "confidence" => "high"}] =
             scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
  end

  test "nonliteral defaults are not substituted, but full-arity calls still resolve" do
    decoder =
      temp_fixture_file("basic", "lib/nonliteral_default_decoder.ex", """
      defmodule NonliteralDefaultDecoder do
        def decode(body, module \\\\ configured_decoder())
        def decode(body, module), do: module.decode(body)
      end

      defmodule LiteralTermDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      """)

    temp_fixture_file("basic", "lib/nonliteral_default_parser.ex", """
    defmodule NonliteralDefaultParser do
      def unknown(conn), do: Consumer.consume(NonliteralDefaultDecoder.decode(conn.params["cursor"]))
      def explicit(conn), do: Consumer.consume(NonliteralDefaultDecoder.decode(conn.params["cursor"], LiteralTermDecoder))
    end
    """)

    assert [%{"file" => ^decoder, "line" => 7, "confidence" => "high"}] =
             scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
  end

  test "branch alternatives preserve request input through decoding" do
    decoder =
      temp_fixture_file("basic", "lib/alternative_decoder.ex", """
      defmodule AlternativeDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      """)

    temp_fixture_file("basic", "lib/alternative_parser.ex", """
    defmodule AlternativeParser do
      def parse(conn, choice) do
        raw = if choice, do: conn.params["cursor"], else: conn.params["other"]
        Consumer.consume(AlternativeDecoder.decode(raw))
      end
    end
    """)

    assert [%{"file" => ^decoder, "line" => 2}] =
             scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
  end

  test "bounded project traversal warns when clause and depth limits prevent a decision" do
    decoder =
      temp_fixture_file("basic", "lib/bounded_decoder.ex", """
      defmodule BoundedDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      """)

    clauses =
      Enum.map_join(1..13, "\n", fn index ->
        "defp many(#{index}, body), do: BoundedDecoder.decode(body)"
      end)

    chain =
      Enum.map_join(1..5, "\n", fn index ->
        "defp hop#{index}(body), do: hop#{index + 1}(body)"
      end)

    temp_fixture_file("basic", "lib/bounded_parser.ex", """
    defmodule BoundedParser do
      #{clauses}
      #{chain}
      defp hop6(body), do: BoundedDecoder.decode(body)
      def by_clauses(conn), do: Consumer.consume(many(1, conn.params["cursor"]))
      def by_depth(conn), do: Consumer.consume(hop1(conn.params["cursor"]))
    end
    """)

    {_stdout, stderr} = scan_io("basic", only: ["Misc.BinToTerm"])
    assert stderr =~ "bounded_parser.ex"
    assert stderr =~ "clause limit"
    assert stderr =~ "depth limit"

    refute Enum.any?(Sobelow.FindingLog.log() |> Map.values() |> List.flatten(), fn {_, finding,
                                                                                     _} ->
             finding.filename == decoder
           end)
  end

  test "nonliteral default dispatch warns when its omitted value cannot be evaluated" do
    temp_fixture_file("basic", "lib/unknown_default_decoder.ex", """
    defmodule UnknownDefaultDecoder do
      def decode(body, module \\\\ choose_decoder())
      def decode(body, module), do: module.decode(body)
    end
    """)

    temp_fixture_file("basic", "lib/unknown_default_parser.ex", """
    defmodule UnknownDefaultParser do
      def parse(conn), do: Consumer.consume(UnknownDefaultDecoder.decode(conn.params["cursor"]))
    end
    """)

    {_stdout, stderr} = scan_io("basic", only: ["Misc.BinToTerm"])
    assert stderr =~ "unknown_default_parser.ex"
    assert stderr =~ "nonliteral default"
  end

  test "guards on encoded aliases cannot validate a later decoded aggregate" do
    decoder =
      temp_fixture_file("basic", "lib/aliased_guard_decoder.ex", """
      defmodule AliasedGuardDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      """)

    temp_fixture_file("basic", "lib/aliased_guard_parser.ex", """
    defmodule AliasedGuardParser do
      def parse(conn) do
        raw = conn.params["cursor"]
        if is_binary(raw), do: Consumer.consume(AliasedGuardDecoder.decode(raw))
      end

      def alternatives(conn, choice) do
        raw = if choice, do: conn.params["cursor"], else: conn.params["other"]
        if is_binary(raw), do: Consumer.consume(AliasedGuardDecoder.decode(raw))
      end
    end
    """)

    assert [%{"file" => ^decoder, "line" => 2, "confidence" => "high"}] =
             scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
  end

  test "oversized alternatives warn rather than silently dropping a request path" do
    decoder =
      temp_fixture_file("basic", "lib/large_branch_decoder.ex", """
      defmodule LargeBranchDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      """)

    branches =
      Enum.map_join(1..13, "\n", fn index ->
        "#{index} -> conn.params[\"cursor\"]"
      end)

    temp_fixture_file("basic", "lib/large_branch_parser.ex", """
    defmodule LargeBranchParser do
      def parse(conn, choice) do
        raw = case choice do
          #{branches}
        end
        Consumer.consume(LargeBranchDecoder.decode(raw))
      end
    end
    """)

    {_stdout, stderr} = scan_io("basic", only: ["Misc.BinToTerm"])
    assert stderr =~ "large_branch_parser.ex"
    assert stderr =~ "alternative limit"

    refute Enum.any?(Sobelow.FindingLog.log() |> Map.values() |> List.flatten(), fn {_, finding,
                                                                                     _} ->
             finding.filename == decoder
           end)
  end

  test "with failure alternatives are bounded and warn for request-bearing values" do
    parser =
      temp_fixture_file("basic", "lib/with_alternatives.ex", """
      defmodule WithAlternatives do
        def parse(conn) do
          with {:ok, raw} <- Base.decode64(conn.params["cursor"]),
               {:ok, raw} <- Base.decode64(raw),
               {:ok, raw} <- Base.decode64(raw),
               {:ok, raw} <- Base.decode64(raw),
               {:ok, raw} <- Base.decode64(raw),
               {:ok, raw} <- Base.decode64(raw),
               {:ok, raw} <- Base.decode64(raw) do
            :ok
          else
            {:error, _} -> :invalid
            _ -> :invalid
          end
        end
      end
      """)

    {_stdout, stderr} = scan_io("basic", only: ["Misc.BinToTerm"])
    assert stderr =~ Path.basename(parser)
    assert stderr =~ "alternative limit"
  end

  test "ignored or unparseable sources are never indexed as project helpers" do
    ignored =
      temp_fixture_file("basic", "lib/ignored_decoder.ex", """
      defmodule IgnoredTermDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      """)

    temp_fixture_file(
      "basic",
      "lib/broken_decoder.ex",
      "defmodule BrokenTermDecoder do\n def decode(\n"
    )

    temp_fixture_file("basic", "lib/filtered_parser.ex", """
    defmodule FilteredParser do
      def parse(conn) do
        Consumer.consume(IgnoredTermDecoder.decode(conn.params["cursor"]))
        Consumer.consume(BrokenTermDecoder.decode(conn.params["cursor"]))
      end
    end
    """)

    {stdout, stderr} =
      scan_io("basic",
        only: ["Misc.BinToTerm"],
        ignored_files: [Path.expand(ignored)],
        summary: true
      )

    assert [] = Jason.decode!(stdout) |> findings_for("Misc.BinToTerm")
    assert stderr =~ "unparseable: 1"
    assert stderr =~ "ignored: 1"
  end

  test "project branch budget bounds nested decisions without dropping completed handoffs" do
    decoder =
      temp_fixture_file("basic", "lib/branch_budget_decoder.ex", """
      defmodule BranchBudgetDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      """)

    branches =
      Enum.map_join(1..130, "\n", fn _ -> "if conn.params[\"choice\"], do: :ok, else: :no" end)

    temp_fixture_file("basic", "lib/branch_budget_parser.ex", """
    defmodule BranchBudgetParser do
      def parse(conn) do
        Consumer.consume(BranchBudgetDecoder.decode(conn.params["cursor"]))
        #{branches}
        Consumer.consume(BranchBudgetDecoder.decode(conn.params["other"]))
      end
    end
    """)

    {_stdout, stderr} = scan_io("basic", only: ["Misc.BinToTerm"])
    assert stderr =~ "branch_budget_parser.ex"
    assert stderr =~ "alternative limit"

    assert [{_, finding, _}] =
             Sobelow.FindingLog.log()
             |> Map.values()
             |> List.flatten()
             |> Enum.filter(fn {_, finding, _} -> finding.filename == decoder end)

    assert finding.vuln_line_no == 2
  end

  test "an exhausted evaluation budget warns instead of silently dropping request provenance" do
    decoder =
      temp_fixture_file("basic", "lib/budget_decoder.ex", """
      defmodule BudgetDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      """)

    calls = Enum.map_join(1..256, "\n", fn _ -> "drop(conn.params[\"cursor\"])" end)

    temp_fixture_file("basic", "lib/budget_parser.ex", """
    defmodule BudgetParser do
      defp drop(_body), do: :ok
      def parse(conn) do
        #{calls}
        Consumer.consume(BudgetDecoder.decode(conn.params["cursor"]))
      end
    end
    """)

    {_stdout, stderr} = scan_io("basic", only: ["Misc.BinToTerm"])
    assert stderr =~ "budget_parser.ex"
    assert stderr =~ "evaluation limit"

    refute Enum.any?(Sobelow.FindingLog.log() |> Map.values() |> List.flatten(), fn {_, finding,
                                                                                     _} ->
             finding.filename == decoder
           end)
  end

  test "recursive request helpers warn, without warning on untracked arguments" do
    temp_fixture_file("basic", "lib/recursive_parser.ex", """
    defmodule RecursiveParser do
      defp recurse(body), do: recurse(body)
      def parse(conn), do: recurse(conn.params["cursor"])
      def unrelated(conn), do: recurse(:fixed) && conn
    end
    """)

    {_stdout, stderr} = scan_io("basic", only: ["Misc.BinToTerm"])
    assert stderr =~ "recursive_parser.ex"
    assert stderr =~ "recursive call"
    assert length(String.split(stderr, "recursive call")) == 2
  end

  test "literal module defaults resolve using their declaration's alias scope" do
    decoder =
      temp_fixture_file("basic", "lib/literal_default_decoder.ex", """
      defmodule LiteralDefaultDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      defmodule DefaultSelector do
        alias LiteralDefaultDecoder, as: TermDecoder
        def decode(body, module \\\\ TermDecoder)
        def decode(body, module), do: module.decode(body)
      end
      """)

    temp_fixture_file("basic", "lib/literal_default_parser.ex", """
    defmodule LiteralDefaultParser do
      def parse(conn), do: Consumer.consume(DefaultSelector.decode(conn.params["cursor"]))
    end
    """)

    assert [%{"file" => ^decoder, "line" => 2, "confidence" => "high"}] =
             scan("basic", only: ["Misc.BinToTerm"]) |> findings_for("Misc.BinToTerm")
  end

  test "a nonliteral trailing default warns even alongside a literal module default" do
    decoder =
      temp_fixture_file("basic", "lib/mixed_default_decoder.ex", """
      defmodule MixedDefaultDecoder do
        def decode(body), do: Plug.Crypto.non_executable_binary_to_term(body, [:safe])
      end
      defmodule DefaultSelector do
        def decode(body, module \\\\ MixedDefaultDecoder, opts \\\\ configured_options())
        def decode(body, module, _opts), do: module.decode(body)
      end
      """)

    temp_fixture_file("basic", "lib/mixed_default_parser.ex", """
    defmodule MixedDefaultParser do
      def unknown(conn), do: Consumer.consume(DefaultSelector.decode(conn.params["cursor"]))
      def explicit(conn), do: Consumer.consume(DefaultSelector.decode(conn.params["cursor"], MixedDefaultDecoder, []))
    end
    """)

    {_stdout, stderr} = scan_io("basic", only: ["Misc.BinToTerm"])
    assert stderr =~ "mixed_default_parser.ex"
    assert stderr =~ "nonliteral default"

    assert [{_, finding, _}] =
             Sobelow.FindingLog.log()
             |> Map.values()
             |> List.flatten()
             |> Enum.filter(fn {_, finding, _} -> finding.filename == decoder end)

    assert finding.vuln_line_no == 2
  end

  test "CLI details explain resource risk independently of decoder protections" do
    help =
      ExUnit.CaptureIO.capture_io(fn ->
        Mix.Tasks.Sobelow.run(["--details", "Misc.BinToTerm", "--private"])
      end)

    assert help =~ "neither `:safe`"
    assert help =~ "not proof of resource safety"
  end
end
