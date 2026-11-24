defmodule Sobelow.PropagationTest do
  use ExUnit.Case, async: true

  alias Sobelow.Parse.Propagation

  defp source(source, file) do
    {Code.string_to_quoted!(source, columns: true), file}
  end

  defp project(sources), do: Propagation.index(sources)

  defp run(project, module, fun, args, opts \\ []) do
    Propagation.run(project, {module, fun, length(args)}, args, opts)
  end

  test "separates module identity and visibility while linking argument to return and consumer" do
    project =
      project([
        source(
          """
          defmodule A do
            defp hidden(value), do: value
            def public(value), do: hidden(value)
            def forward(value), do: B.accept(public(value))
            def other(value), do: B.hidden(value)
          end
          """,
          "a.ex"
        ),
        source(
          """
          defmodule B do
            def accept(value), do: Consumer.accept(value)
            defp hidden(value), do: Consumer.unreachable(value)
          end
          """,
          "b.ex"
        )
      ])

    source = {:source, :payload}
    assert run(project, [:A], :public, [source]).returns == [source]
    found = run(project, [:A], :forward, [source])

    assert Enum.map(found.consumers, fn {_, _, entry} -> {entry.file, entry.name} end) ==
             [{"b.ex", :accept}]

    assert found.truncated == MapSet.new()

    assert Enum.any?(run(project, [:A], :other, [source]).consumers, fn {_, _, entry} ->
             entry.file == "a.ex"
           end)
  end

  test "associates declaration defaults with each implementation clause, not other modules" do
    project =
      project([
        source(
          ~S"""
          defmodule Outer do
            def child(value), do: Inner.consume(value)
            defmodule Inner do
              def consume(value, marker \\ :public)
              def consume(value, :public), do: Consumer.use(value)
              def consume(value, _), do: :ok
            end
          end
          """,
          "outer.ex"
        )
      ])

    found = run(project, [:Outer], :child, [{:source, :payload}])
    assert [{_node, [{:source, :payload}], %{module: [:Outer, :Inner]}}] = found.consumers
  end

  test "alternatives retain aggregate shape and do not treat guards as sanitizers" do
    project =
      project([
        source(
          """
          defmodule Shape do
            def consume(%{item: item} = whole) when is_integer(item) do
              Consumer.checked(item)
              Consumer.unchecked(whole)
            end
            def branch(value, choice) do
              item = if choice, do: value, else: :fixed
              Consumer.use(item)
            end
          end
          """,
          "shape.ex"
        )
      ])

    found = run(project, [:Shape], :consume, [{:map, [item: {:source, :item}]}])

    assert Enum.sort(
             Enum.map(found.consumers, fn {node, values, _} ->
               {Macro.to_string(node), values}
             end)
           ) == [
             {"Consumer.checked(item)", [{:source, :item}]},
             {"Consumer.unchecked(whole)", [{:map, [item: {:source, :item}]}]}
           ]

    assert [{_, [value], _}] = run(project, [:Shape], :branch, [{:source, :item}, nil]).consumers
    assert {:choices, [{:source, :item}, :fixed]} = value
  end

  test "resolved aliases, imports and bounded literal module alternatives follow only indexed calls" do
    project =
      project([
        source(
          """
          defmodule ConsumerA do
            def pass(value), do: value
          end
          defmodule ConsumerB do
            def pass(value), do: Consumer.finish(value)
          end
          """,
          "helpers.ex"
        ),
        source(
          """
          defmodule Caller do
            alias ConsumerA, as: A
            alias ConsumerB, as: B
            import ConsumerA, only: [pass: 1]
            def imported(value), do: pass(value)
            def dynamic(value, choice) do
              module = if choice, do: A, else: B
              module.pass(value)
            end
            def unknown(value, module), do: module.pass(value)
          end
          """,
          "caller.ex"
        )
      ])

    source = {:source, :payload}
    assert run(project, [:Caller], :imported, [source]).returns == [source]
    found = run(project, [:Caller], :dynamic, [source, nil])

    assert Enum.any?(found.consumers, fn {node, _, entry} ->
             entry.module == [:ConsumerB] and Macro.to_string(node) == "Consumer.finish(value)"
           end)

    assert run(project, [:Caller], :unknown, [source, nil]).consumers != []
  end

  test "normalizes alternatives, evaluates literal defaults and preserves protocol namespaces" do
    project =
      project([
        source(
          ~S"""
          defmodule Defaults do
            def pair(value, count \\ 0, module \\ ConsumerA)
            def pair(value, _count, _module), do: value
            def forwarded(value), do: pair(value)
            def branches(value), do: if(true, do: value, else: :ok)
          end
          defprotocol Gateway do
            def handoff(value)
          end
          defmodule Gateway do
            def handoff(value), do: value
          end
          defimpl Gateway, for: Integer do
            def handoff(value), do: Consumer.ignore(value)
          end
          """,
          "defaults.ex"
        )
      ])

    source = {:source, :payload}
    assert run(project, [:Defaults], :forwarded, [source]).returns == [source]
    assert run(project, [:Defaults], :branches, [source]).returns == [source, :ok]
    assert length(project.functions[{[:Gateway], :handoff, 1}]) == 1
  end

  test "lists and tuples retain nested sources through pattern extraction" do
    project =
      project([
        source(
          """
          defmodule Shapes do
            def construct(value), do: {[value], %{selected: value}}
            def extract({[value], _rest}), do: Consumer.use(value)
          end
          """,
          "shapes.ex"
        )
      ])

    source = {:source, :payload}

    assert [{:tuple, [{:list, [^source]}, {:map, [selected: ^source]}]}] =
             run(project, [:Shapes], :construct, [source]).returns

    assert [{_, [^source], _}] =
             run(project, [:Shapes], :extract, [{:tuple, [{:list, [source]}, :ok]}]).consumers
  end

  test "literal defaults use the declaration scope and produce normalized values" do
    project =
      project([
        source(
          ~S"""
          defmodule DefaultValues do
            alias ConsumerA, as: Receiver
            def forward(value, module \\ Receiver, shape \\ %{item: :fixed})
            def forward(value, module, %{item: item}), do: module.pass({value, item})
          end
          defmodule ConsumerA do
            def pass(value), do: Consumer.accept(value)
          end
          """,
          "defaults.ex"
        )
      ])

    result = run(project, [:DefaultValues], :forward, [{:source, :payload}])

    assert [{_, [{:tuple, [{:source, :payload}, :fixed]}], _}] = result.consumers
    assert result.truncated == MapSet.new()
  end

  test "nontrailing defaults align by position for each accepted call arity" do
    project =
      project([
        source(
          ~S"""
          defmodule MixedDefaults do
            def pair(first \\ :first, middle, last \\ :last)
            def pair(first, middle, last), do: Consumer.observe({first, middle, last})
          end
          """,
          "mixed.ex"
        )
      ])

    source = {:source, :payload}

    assert [{_, [{:tuple, [:first, ^source, :last]}], _}] =
             run(project, [:MixedDefaults], :pair, [source]).consumers

    assert [{_, [{:tuple, [:first, :override, ^source]}], _}] =
             run(project, [:MixedDefaults], :pair, [:override, source]).consumers
  end

  test "a partially resolved module choice retains the unknown consumer and return" do
    project =
      project([
        source(
          """
          defmodule PublicHelper do
            def pass(_value), do: :discarded
          end
          defmodule Selector do
            def handoff(value, unknown) do
              module = if value, do: PublicHelper, else: unknown
              module.pass(value)
            end
          end
          """,
          "choices.ex"
        )
      ])

    result = run(project, [:Selector], :handoff, [{:source, :payload}, nil])
    assert [{node, [{:source, :payload}], _}] = result.consumers
    assert Macro.to_string(node) == "module.pass(value)"
    assert :discarded in result.returns
    assert {:unknown, [{:source, :payload}]} in result.returns
    assert MapSet.member?(result.truncated, :dynamic_receiver)
  end

  test "local definitions take precedence over imports and private clauses stay private" do
    project =
      project([
        source(
          """
          defmodule Importer do
            import Other, only: [use: 1]
            def use(value), do: value
            defp private(value), do: Consumer.private(value)
            def direct(value), do: use(value)
          end
          defmodule Other do
            def use(value), do: Consumer.imported(value)
          end
          defmodule Outsider do
            def handoff(value), do: Importer.private(value)
          end
          """,
          "visibility.ex"
        )
      ])

    source = {:source, :payload}
    assert run(project, [:Importer], :direct, [source]).returns == [source]
    assert run(project, [:Importer], :direct, [source]).consumers == []
    outside = run(project, [:Outsider], :handoff, [source])
    assert [{node, [^source], %{module: [:Outsider]}}] = outside.consumers
    assert Macro.to_string(node) == "Importer.private(value)"
  end

  test "map updates and dynamic keys do not lose their source labels" do
    project =
      project([
        source(
          """
          defmodule Maps do
            def update(map, value) do
              modified = %{map | other: :fixed}
              Consumer.observe(modified.selected)
              Consumer.observe(%{value => :fixed})
            end
          end
          """,
          "maps.ex"
        )
      ])

    source = {:source, :payload}
    found = run(project, [:Maps], :update, [{:map, [selected: source]}, source])
    assert length(found.consumers) == 2
    assert Enum.all?(found.consumers, fn {_, values, _} -> values != [nil] end)
  end

  test "branch limits keep late sources, and with failures remain possible" do
    project =
      project([
        source(
          """
          defmodule Branches do
            def cap(value) do
              case value do
                0 -> :a
                1 -> :b
                2 -> :c
                3 -> :d
                4 -> :e
                5 -> :f
                6 -> :g
                7 -> :h
                8 -> :i
                9 -> :j
                10 -> :k
                11 -> :l
                12 -> value
              end
            end
            def failure(value) do
              with {:ok, _item} <- value do
                :fixed
              else
                {:error, _reason} -> :handled
              end
            end
          end
          """,
          "branches.ex"
        )
      ])

    source = {:source, :payload}
    branches = run(project, [:Branches], :cap, [source])
    assert MapSet.member?(branches.truncated, :clause_limit)
    assert [{:unknown, possibilities}] = branches.returns
    assert source in possibilities

    failed = run(project, [:Branches], :failure, [source])
    assert source in failed.returns
    assert :handled in failed.returns
  end

  test "alternatives above the precision cap retain a late source" do
    clauses = for i <- 0..10, do: "#{i} -> :fixed_#{i}"

    project =
      project([
        source(
          """
          defmodule Limit do
            def select(value) do
              case value do
                #{Enum.join(clauses, "\n")}
                11 -> if(value, do: :extra, else: value)
              end
            end
          end
          """,
          "limit.ex"
        )
      ])

    source = {:source, :payload}
    found = run(project, [:Limit], :select, [source])
    assert MapSet.member?(found.truncated, :alternative_limit)
    assert [{:unknown, possibilities}] = found.returns
    assert source in possibilities
  end

  test "unresolved paths and exhausted budgets remain explicit and do not imply safety" do
    project =
      project([
        source(
          ~S"""
          defmodule Bounds do
            def recursive(value), do: recursive(value)
            def other(value, module \\ dynamic())
            def other(value, _module), do: Consumer.use(value)
            def gate(value), do: if(value, do: Consumer.use(value))
          end
          """,
          "bounds.ex"
        )
      ])

    source = {:source, :payload}

    recursive = run(project, [:Bounds], :recursive, [source])
    assert MapSet.member?(recursive.truncated, :recursive_call)
    assert [{:unknown, [^source]}] = recursive.returns

    other = run(project, [:Bounds], :other, [source])
    assert MapSet.member?(other.truncated, :nonliteral_default)
    assert {:unknown, [source]} in other.returns

    gate = run(project, [:Bounds], :gate, [source], max_work: 1)
    assert MapSet.member?(gate.truncated, :work_limit)
    assert [{:unknown, possibilities}] = gate.returns
    assert source in possibilities
  end
end
