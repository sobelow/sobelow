defmodule Sobelow.Parse do
  @moduledoc false

  @operators [
    :+,
    :-,
    :!,
    :^,
    :not,
    :"~~~",
    :*,
    :/,
    :++,
    :--,
    :..,
    :<>,
    :<<<,
    :>>>,
    :~>>,
    :<<~,
    :>,
    :<,
    :>=,
    :<=,
    :==,
    :!=,
    :=~,
    :===,
    :!==,
    :&&,
    :&&&,
    :and,
    :||,
    :|||,
    :or,
    :=,
    :|
  ]

  def ast(filepath) do
    Sobelow.Scan.fetch({:ast, Path.expand(filepath), Sobelow.get_env(:skip)}, fn ->
      case read_file(filepath) do
        {:ok, content} -> parse(content, filepath)
        {:error, reason} -> unreadable_source(filepath, reason)
      end
    end)
  end

  @doc false
  # `ast/1`, plus a warning for any `# sobelow_skip` comment that could not be
  # read. An unrecognised comment is otherwise dropped in silence, which looks
  # exactly like a skip that did not apply — the two are indistinguishable to
  # someone whose comment simply has a stray space in it.
  #
  # Only for the one pass over every file in the project. `read_file/1` runs six
  # times for a router, which is where pipeline skips live, so warning from
  # there would repeat itself.
  def ast_with_skip_warnings(filepath) do
    case read_file(filepath) do
      {:ok, content} ->
        Sobelow.Scan.fetch({:skip_warnings, Path.expand(filepath)}, fn ->
          warn_unrecognised_skips(filepath, content)
        end)

        ast(filepath)

      {:error, reason} ->
        unreadable_source(filepath, reason)
    end
  end

  defp unreadable_source(filepath, reason) do
    Sobelow.Scan.record(
      filepath,
      :unreadable,
      "Could not read #{filepath}: #{:file.format_error(reason)}"
    )

    IO.puts(:stderr, "Could not read #{filepath}: #{:file.format_error(reason)}; skipping it.")
    {}
  end

  defp parse(content, filepath) do
    case Code.string_to_quoted(content, columns: true, file: filepath) do
      {:ok, ast} ->
        Sobelow.Scan.record(filepath, :scanned)
        ast

      {:error, {location, err, token}} ->
        syntax_error(filepath, location, err, token)
    end
  end

  defp syntax_error(filepath, location, err, token) do
    message = "#{filepath}:#{format_location(location)} #{format_error(err, token)}"
    Sobelow.Scan.record(filepath, :unparseable, message)

    if Application.get_env(:sobelow, :strict) do
      message = "#{filepath}:#{format_location(location)} #{format_error(err, token)}"
      IO.puts(:stderr, message)
      System.halt(2)
    else
      {}
    end
  end

  @doc false
  # Some errors are reported as a `{prefix, suffix}` pair around the offending token.
  def format_error({prefix, suffix}, token), do: "#{prefix}#{token}#{suffix}"
  def format_error(err, token) when is_binary(err), do: "#{err}#{token}"
  def format_error(err, token), do: "#{inspect(err)}#{token}"

  @doc false
  # Elixir >= 1.13 reports the error location as a keyword list of metadata.
  # Older versions report a bare line number.
  def format_location(location) when is_list(location) do
    line = Keyword.get(location, :line)
    column = Keyword.get(location, :column)

    case {line, column} do
      {nil, _} -> ""
      {line, nil} -> "#{line}:"
      {line, column} -> "#{line}:#{column}:"
    end
  end

  def format_location(line) when is_integer(line), do: "#{line}:"
  def format_location(_), do: ""

  # A `# sobelow_skip` comment, rewritten into a module attribute so it survives
  # into the AST. Whitespace is deliberately loose: the spacing around the
  # marker and inside the list carries no meaning, and being strict about it
  # only produced comments that looked right and did nothing.
  @skip_comment ~r/#\s*sobelow_skip\s*(\[\s*"[^"]+"(?:\s*,\s*"[^"]+")*\s*,?\s*\])/

  # Anything that looks like an attempt at one. Requiring the bracket keeps
  # prose that merely mentions `# sobelow_skip` from being flagged.
  @skip_comment_attempt ~r/#\s*sobelow_skip\s*\[/

  defp read_file(filepath) do
    case Sobelow.Scan.source(filepath) do
      {:ok, content} ->
        if Sobelow.get_env(:skip) do
          {:ok, String.replace(content, @skip_comment, "@sobelow_skip \\g{1}")}
        else
          {:ok, content}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Runs against the rewritten content, so every comment that was understood has
  # already become an attribute and whatever still reads as a skip comment is
  # one we could not parse.
  defp warn_unrecognised_skips(filepath, content) do
    if Sobelow.get_env(:skip) do
      content
      |> String.split("\n")
      |> Enum.with_index(1)
      |> Enum.each(fn {line, line_no} ->
        if Regex.match?(@skip_comment_attempt, line),
          do: warn_unrecognised_skip(filepath, line_no)
      end)
    end
  end

  defp warn_unrecognised_skip(filepath, line_no) do
    IO.puts(
      :stderr,
      "#{filepath}:#{line_no}: could not read this `# sobelow_skip` comment, so it was " <>
        "ignored. Expected a list of double-quoted checks, " <>
        ~s(for example: # sobelow_skip ["Config.CSRF"])
    )
  end

  def get_meta_funs(filepath) when is_binary(filepath) do
    ast = ast(filepath)
    get_meta_funs(ast)
  end

  def get_meta_funs(ast) do
    init_acc = %{def_funs: [], use_funs: [], import_funs: [], module_attrs: []}
    {_, acc} = Macro.prewalk(ast, init_acc, &get_meta_funs(&1, &2))

    # A `@sobelow_skip` that annotates a pipeline has already been consumed by
    # `get_pipelines_with_skips/1`. Leaving it in `def_funs` would let
    # `Sobelow.combine_skips/2` bind it to the next function in the file as well.
    #
    # Only a file that actually carries a skip attribute can have one rejected,
    # and virtually none do, so the second walk is gated on the first one having
    # found something. Under `--skip` this is the difference between paying for
    # an extra full traversal of every scanned file and paying for none.
    if Enum.any?(acc.def_funs, &skip_attr?/1) do
      consumed = pipeline_skip_attrs(ast)
      Map.update!(acc, :def_funs, &Enum.reject(&1, fn fun -> MapSet.member?(consumed, fun) end))
    else
      acc
    end
  end

  @doc false
  # `use` and `import` belong to a module, not a whole source file. Keep
  # definitions beside the declarations that can affect their meaning.
  def get_module_meta_funs(ast) do
    {_, modules} =
      Macro.prewalk(ast, [], fn
        {:defmodule, _, [_, [do: body]]} = node, acc -> {node, [body | acc]}
        node, acc -> {node, acc}
      end)

    case modules do
      [] ->
        [get_meta_funs(ast)]

      bodies ->
        bodies
        |> Enum.reverse()
        |> Enum.map(fn body ->
          body
          |> Macro.prewalk(fn
            {:defmodule, _, _} -> {}
            node -> node
          end)
          |> get_meta_funs()
        end)
    end
  end

  @doc false
  def file_metadata(ast) do
    empty = %{def_funs: [], use_funs: [], import_funs: [], module_attrs: []}

    initial = %{
      file: empty,
      modules: %{},
      current: nil,
      parents: [],
      count: 0,
      captured_depth: 0,
      fallback?: false
    }

    {_, metadata} = Macro.traverse(ast, initial, &metadata_pre/2, &metadata_post/2)

    consumed =
      if Enum.any?(metadata.file.def_funs, &skip_attr?/1),
        do: pipeline_skip_attrs(ast),
        else: MapSet.new()

    clean = fn meta ->
      Map.update!(meta, :def_funs, &Enum.reject(&1, fn fun -> MapSet.member?(consumed, fun) end))
    end

    file = clean.(metadata.file)

    contexts =
      cond do
        metadata.fallback? -> get_module_meta_funs(ast)
        metadata.count == 0 -> [file]
        true -> Enum.map(0..(metadata.count - 1), &clean.(Map.fetch!(metadata.modules, &1)))
      end

    {file, contexts}
  end

  defp metadata_pre(node, metadata) do
    {_, file} = get_meta_funs(node, metadata.file)
    metadata = %{metadata | file: file}

    metadata =
      if captured_metadata?(node),
        do: %{metadata | captured_depth: metadata.captured_depth + 1},
        else: metadata

    case node do
      {:defmodule, _, [name, [do: _body]]} ->
        empty = %{def_funs: [], use_funs: [], import_funs: [], module_attrs: []}
        %{count: id, current: parent} = metadata

        metadata = %{
          metadata
          | modules: Map.put(metadata.modules, id, empty),
            current: id,
            count: id + 1,
            parents: [parent | metadata.parents],
            fallback?:
              metadata.fallback? or metadata.captured_depth > 0 or
                not literal_module_name?(name)
        }

        {node, metadata}

      {:defmodule, _, _} ->
        {node, %{metadata | fallback?: true}}

      _ ->
        modules =
          if metadata.current != nil do
            Map.update!(metadata.modules, metadata.current, fn meta ->
              elem(get_meta_funs(node, meta), 1)
            end)
          else
            metadata.modules
          end

        {node, %{metadata | modules: modules}}
    end
  end

  defp metadata_post({:defmodule, _, [_, [do: _]]} = node, metadata) do
    [parent | rest] = metadata.parents
    {node, %{metadata | current: parent, parents: rest}}
  end

  defp metadata_post(node, metadata) do
    metadata =
      if captured_metadata?(node),
        do: %{metadata | captured_depth: metadata.captured_depth - 1},
        else: metadata

    {node, metadata}
  end

  # The old extraction strips nested modules out of captured definitions and
  # attributes. Those unusual containers need its rewritten AST, rather than
  # the original node retained by the combined traversal.
  defp captured_metadata?({name, _, _}) when name in [:def, :defp, :defmacro, :use, :import, :@],
    do: true

  defp captured_metadata?(_node), do: false

  defp literal_module_name?({:__aliases__, _, parts}), do: Enum.all?(parts, &is_atom/1)
  defp literal_module_name?(name), do: is_atom(name)

  defp skip_attr?({:@, _, [{:sobelow_skip, _, _}]}), do: true
  defp skip_attr?(_), do: false

  @doc false
  # Every `pipeline` macro in the AST, paired with the skips from any
  # immediately preceding `@sobelow_skip` attributes (rewritten from
  # `# sobelow_skip` comments by `read_file/1` when `--skip` is set).
  #
  # Phoenix router pipelines are macros, not `def`/`defp`, so the function-level
  # skip association in `Sobelow.combine_skips/2` never reaches them.
  #
  # Collection and association are deliberately separate walks: `get_funs_of_type/2`
  # finds pipelines wherever they appear, so a pipeline nested in something other
  # than a plain block (say, inside an `if`) is still scanned — just without skips.
  def get_pipelines_with_skips(ast) do
    skips = Map.new(skip_associations(ast), fn {pipeline, skips, _attrs} -> {pipeline, skips} end)

    ast
    |> get_funs_of_type(:pipeline)
    |> Enum.reverse()
    |> Enum.map(&{&1, Map.get(skips, &1, [])})
  end

  defp pipeline_skip_attrs(ast) do
    ast
    |> skip_associations()
    |> Enum.flat_map(fn {_pipeline, _skips, attrs} -> attrs end)
    |> MapSet.new()
  end

  # `read_file/1` only rewrites skip comments into attributes under `--skip`, so
  # without it there is nothing to associate and the walk can be skipped entirely.
  defp skip_associations(ast) do
    if Sobelow.get_env(:skip) do
      {_, acc} = Macro.prewalk(ast, [], &collect_skip_associations/2)
      acc
    else
      []
    end
  end

  defp collect_skip_associations({:__block__, _, stmts} = ast, acc) when is_list(stmts) do
    {ast, acc ++ associate_skips_with_pipelines(stmts)}
  end

  defp collect_skip_associations(ast, acc), do: {ast, acc}

  # `@sobelow_skip` attributes bind to the next `pipeline` in the same block. Any
  # other statement in between clears them, mirroring the way a function-level
  # skip has to sit immediately above its `def`. A pipeline that carries a skip
  # always has at least two statements in its block, so it always has a
  # `__block__` to be found in.
  defp associate_skips_with_pipelines(statements) do
    {associations, _pending} =
      Enum.reduce(statements, {[], []}, fn
        {:@, _, [{:sobelow_skip, _, [skips]}]} = attr, {acc, pending} when is_list(skips) ->
          {acc, pending ++ [{attr, skips}]}

        {:pipeline, _, _} = pipeline, {acc, pending} ->
          {[{pipeline, pending} | acc], []}

        _, {acc, _pending} ->
          {acc, []}
      end)

    Enum.map(associations, fn {pipeline, pending} ->
      {pipeline, Enum.flat_map(pending, &elem(&1, 1)), Enum.map(pending, &elem(&1, 0))}
    end)
  end

  def get_meta_funs({:@, _, [{:sobelow_skip, _, _}]} = ast, acc) do
    if Sobelow.get_env(:skip) do
      {ast, Map.update!(acc, :def_funs, &[ast | &1])}
    else
      {ast, acc}
    end
  end

  def get_meta_funs({:def, _, nil} = ast, acc), do: {ast, acc}
  def get_meta_funs({:defp, _, nil} = ast, acc), do: {ast, acc}
  def get_meta_funs({:@, _, [{_, _, nil}]} = ast, acc), do: {ast, acc}

  def get_meta_funs({:def, _, _} = ast, acc) do
    {ast, Map.update!(acc, :def_funs, &[ast | &1])}
  end

  def get_meta_funs({:defp, _, _} = ast, acc) do
    {ast, Map.update!(acc, :def_funs, &[ast | &1])}
  end

  def get_meta_funs({:use, _, _} = ast, acc) do
    {ast, Map.update!(acc, :use_funs, &[ast | &1])}
  end

  def get_meta_funs({:import, _, _} = ast, acc) do
    {ast, Map.update!(acc, :import_funs, &[ast | &1])}
  end

  def get_meta_funs({:@, _, [attr | _]} = ast, acc) do
    {ast, Map.update!(acc, :module_attrs, &[attr | &1])}
  end

  def get_meta_funs(ast, acc), do: {ast, acc}

  def get_meta_template_funs(filepath) do
    case Sobelow.Scan.fetch({:template, Path.expand(filepath)}, fn -> template_ast(filepath) end) do
      {:ok, ast} -> get_meta_template_fun(ast)
      :error -> %{raw: [], ast: {}}
    end
  end

  # A template we cannot parse should be skipped like an unparseable `.ex` file,
  # not abort the whole scan.
  defp template_ast(filepath) do
    case Sobelow.Scan.source(filepath) do
      {:ok, source} ->
        ast =
          if Path.extname(filepath) == ".heex" do
            source |> Sobelow.HEEx.ast(filepath) |> heex_assigns()
          else
            EEx.compile_string(source, file: filepath)
          end

        Sobelow.Scan.record(filepath, :scanned)
        {:ok, ast}

      {:error, reason} ->
        message = "Could not read #{filepath}: #{:file.format_error(reason)}"
        Sobelow.Scan.record(filepath, :unreadable, message)
        IO.puts(:stderr, message <> "; skipping it.")
        :error
    end
  rescue
    e in EEx.SyntaxError ->
      Sobelow.Scan.record(filepath, :unparseable, Exception.message(e))

      if Application.get_env(:sobelow, :strict) do
        IO.puts(:stderr, Exception.message(e))
        System.halt(2)
      else
        :error
      end
  end

  @doc false
  def get_heex_raw_funs(ast, file \\ "inline HEEx") do
    {_, raw} =
      Macro.prewalk(ast, [], fn
        {:sigil_H, meta, [{:<<>>, literal_meta, [source]}, _]} = node, acc
        when is_binary(source) ->
          line_offset =
            if Keyword.get(meta, :delimiter) in ["\"\"\"", "'''"] do
              Keyword.get(meta, :line, 0)
            else
              Keyword.get(meta, :line, 1) - 1
            end

          found =
            source
            |> inline_heex_ast(file, line_offset + 1)
            |> shift_inline_columns(meta, literal_meta, line_offset + 1)
            |> heex_assigns()
            |> get_meta_template_fun()
            |> Map.fetch!(:raw)

          {node, found ++ acc}

        node, acc ->
          {node, acc}
      end)

    raw
  end

  defp inline_heex_ast(source, file, line) do
    Sobelow.HEEx.ast(source, file, line)
  rescue
    e in EEx.SyntaxError ->
      Sobelow.Scan.record(file, :unparseable, Exception.message(e))

      if Sobelow.get_env(:strict) do
        IO.puts(:stderr, Exception.message(e))
        System.halt(2)
      end

      {}
  end

  defp shift_inline_columns(ast, sigil, literal, first_line) do
    heredoc? = Keyword.get(sigil, :delimiter) in ["\"\"\"", "'''"]
    indentation = Keyword.get(literal, :indentation, 0)

    prefix =
      if is_integer(sigil[:column]),
        do: sigil[:column] + 1 + String.length(Keyword.get(sigil, :delimiter, "\"")),
        else: 0

    Macro.prewalk(ast, fn
      {name, meta, args} = node when is_list(meta) ->
        offset =
          if heredoc?,
            do: indentation,
            else: if(Keyword.get(meta, :line) == first_line, do: prefix, else: 0)

        if is_integer(meta[:column]),
          do: {name, Keyword.update!(meta, :column, &(&1 + offset)), args},
          else: node

      node ->
        node
    end)
  end

  # The EEx engine represents `@name` as an access on `assigns`. Reuse that
  # representation so existing taint extraction and template correlation see
  # the same variable for both EEx and HEEx expressions.
  defp heex_assigns(ast) do
    Macro.prewalk(ast, fn
      {:@, meta, [{name, _, nil}]} when is_atom(name) ->
        {{:., meta, [{:__aliases__, meta, [:EEx, :Engine]}, :fetch_assign!]}, meta,
         [{:var!, meta, [{:assigns, meta, EEx.Engine}]}, name]}

      node ->
        node
    end)
  end

  def get_meta_template_fun(ast) do
    init_acc = %{raw: [], ast: ast}
    {_, acc} = Macro.prewalk(ast, init_acc, &get_meta_template_fun(&1, &2))
    acc
  end

  # This is some minor code duplication, but feels worth it
  def get_meta_template_fun({:|>, _, [_, {:raw, _, _}]} = ast, acc) do
    {ast, Map.update!(acc, :raw, &[ast | &1])}
  end

  def get_meta_template_fun({:raw, _, _} = ast, acc) do
    {ast, Map.update!(acc, :raw, &[ast | &1])}
  end

  def get_meta_template_fun({{:., _, [{:__aliases__, _, modules}, :raw]}, _, _} = ast, acc) do
    if List.last(modules) == :HTML,
      do: {ast, Map.update!(acc, :raw, &[ast | &1])},
      else: {ast, acc}
  end

  def get_meta_template_fun(ast, acc), do: {ast, acc}

  def get_fun_vars_and_meta(fun, idx, type, module) do
    {params, {fun_name, line_no}} = get_fun_declaration(fun)

    pipefuns = get_funs_from_pipe(fun, type, module)
    pipevars = get_pipefuns_vars(pipefuns, fun, idx)

    vars =
      (get_funs(fun, type, module) -- pipefuns)
      |> get_funs_vars(idx, type, module)

    {vars ++ pipevars, params, {fun_name, line_no}}
  end

  def get_erlang_fun_vars_and_meta(fun, idx, type, module) do
    {params, {fun_name, line_no}} = get_fun_declaration(fun)

    pipefuns = get_erlang_funs_from_pipe(fun, type, module)
    pipevars = get_pipefuns_vars(pipefuns, fun, idx)

    vars =
      (get_erlang_aliased_funs_of_type(fun, type, module) -- pipefuns)
      |> get_funs_vars(idx, type, module)

    {vars ++ pipevars, params, {fun_name, line_no}}
  end

  defp get_funs(fun, type, module) do
    if Sobelow.Lexical.active?() and module != nil do
      target =
        case module do
          {:required, target} -> target
          target -> target
        end

      get_aliased_funs_of_type(fun, type, target) ++
        Enum.filter(get_funs_of_type(fun, type), &Sobelow.Lexical.unqualified?(&1, target))
    else
      legacy_funs(fun, type, module)
    end
  end

  defp legacy_funs(fun, type, nil), do: get_funs_of_type(fun, type)

  defp legacy_funs(fun, type, module) when is_list(module),
    do: get_aliased_funs_of_type(fun, type, module)

  defp legacy_funs(fun, type, {:required, module}),
    do: get_aliased_funs_of_type(fun, type, module)

  defp legacy_funs(fun, type, module),
    do: get_aliased_funs_of_type(fun, type, module) ++ get_funs_of_type(fun, type)

  defp get_funs_from_pipe(fun, type, module) do
    fun
    |> get_pipe_funs()
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(fn node ->
      case module do
        nil ->
          get_piped_funs_of_type(node, type)

        {:required, target} ->
          qualified_pipe(node, type, target)

        target when is_list(target) ->
          qualified_pipe(node, type, target)

        target ->
          if Sobelow.Lexical.active?(),
            do: qualified_pipe(node, type, target),
            else: qualified_pipe(node, type, target) ++ unqualified_pipe(node, type, target)
      end
    end)
    |> Enum.uniq()
  end

  defp qualified_pipe(node, type, target) do
    get_piped_aliased_funs_of_type(node, type, target) ++
      if(Sobelow.Lexical.active?(), do: unqualified_pipe(node, type, target), else: [])
  end

  defp unqualified_pipe(node, type, target) do
    get_piped_funs_of_type(node, type)
    |> Enum.filter(fn node ->
      not Sobelow.Lexical.active?() or Sobelow.Lexical.unqualified?(node, target, 1)
    end)
  end

  def get_erlang_funs_from_pipe(fun, type, module) do
    get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&get_piped_erlang_aliased_funs_of_type(&1, type, module))
    |> Enum.uniq()
  end

  defp get_funs_vars(funs, idx, _type, _module) do
    funs
    |> Enum.map(&{&1, extract_opts(&1, idx)})
    |> Enum.map(&normalize_finding/1)
    |> Enum.reject(fn {_, vars} ->
      is_list(vars) && Enum.empty?(vars)
    end)
  end

  defp get_pipefuns_vars(pipefuns, fun, 0) do
    pipefuns
    |> Enum.map(&{&1, get_pipe_val(fun, &1)})
    |> Enum.map(&normalize_finding/1)
    |> Enum.reject(fn {_, vars} ->
      is_list(vars) && Enum.empty?(vars)
    end)
  end

  defp get_pipefuns_vars(pipefuns, _fun, idx) do
    idx = idx - 1

    pipefuns
    |> Enum.map(&{&1, extract_opts(&1, idx)})
    |> Enum.map(&normalize_finding/1)
    |> Enum.reject(fn {_, vars} ->
      is_list(vars) && Enum.empty?(vars)
    end)
  end

  def normalize_finding({finding, opts}) when is_list(opts) do
    {finding, List.flatten(opts)}
  end

  # This handles normalizations for the case where the finding is a dot-access tuple
  def normalize_finding({finding, {:., _, [{var, _, _}, field]}}) when is_atom(field) do
    {finding, "#{atom_to_string(var)}.#{atom_to_string(field)}"}
  end

  def normalize_finding({finding, opt}) do
    {finding, [opt]}
  end

  defp atom_to_string(atom) when is_atom(atom), do: Atom.to_string(atom)

  def get_erlang_funs_of_type(ast, type) do
    indexed_funs(ast, :qualified, type, &get_erlang_funs_of_type(&1, &2, type, :erlang))
  end

  def get_erlang_funs_of_type({{:., _, [module, type]}, _, _} = ast, acc, type, module) do
    {ast, [ast | acc]}
  end

  def get_erlang_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type, module) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_erlang_funs_of_type(fun_cap, acc, type, module)
  end

  def get_erlang_funs_of_type(ast, acc, _type, _module), do: {ast, acc}

  def get_erlang_aliased_funs_of_type(ast, type, module) do
    indexed_funs(ast, :qualified, type, &get_erlang_funs_of_type(&1, &2, type, module))
  end

  def get_piped_erlang_aliased_funs_of_type(ast, type, module) do
    case ast do
      {{:., _, [^module, ^type]}, _, _} ->
        [ast]

      _ ->
        []
    end
  end

  def get_funs_by_module(ast, module) do
    {_, acc} = Macro.prewalk(ast, [], &contains_module(&1, &2, module))
    acc
  end

  def get_assigns_from(fun, module) when is_list(module) do
    get_funs_of_type(fun, :=)
    |> Enum.filter(&contains_module?(&1, module))
    |> Enum.map(&get_assign/1)
  end

  defp contains_module?(ast, module) do
    {_, acc} = Macro.prewalk(ast, [], &contains_module(&1, &2, module))
    acc != []
  end

  defp contains_module({{:., _, [{:__aliases__, _, module}, _]}, _, _} = ast, acc, module) do
    {module, [ast | acc]}
  end

  defp contains_module(ast, acc, _), do: {ast, acc}

  defp get_assign({_, _, [{val, _, _} | _]}), do: val
  defp get_assign(_), do: ""

  ## This is used to get aliased function calls such as `File.read`
  ## or `Ecto.Adapters.SQL.query`.
  ##
  ## This splits the call between strict and and standard, because there
  ## are some instances where we can be more certain of the alias contents.
  ## For instance, when using stdlib features such as `File.read` the alias
  ## list will be [:File]. For functions like `Ecto.Adapters.SQL.query`, there is less
  ## certainty because the Module has likely been aliased. The alias list
  ## could be [:Ecto, :Adapters, :SQL], just [:SQL], or something else entirely.
  ##
  ## Will consider flagging strict/standard separately depending on how this
  ## works in practice.
  def get_aliased_funs_of_type(ast, type, module) when is_list(module) do
    indexed_funs(ast, :qualified, type, &get_strict_aliased_funs_of_type(&1, &2, type, module))
  end

  def get_aliased_funs_of_type(ast, type, module) do
    indexed_funs(ast, :qualified, type, &get_aliased_funs_of_type(&1, &2, type, module))
  end

  def get_strict_aliased_funs_of_type(
        {{:., _, [{:__aliases__, _, aliases}, type]}, _, _opts} = ast,
        acc,
        type,
        module
      ) do
    if alias_matches?(ast, aliases, module) do
      {ast, [ast | acc]}
    else
      {ast, acc}
    end
  end

  def get_strict_aliased_funs_of_type(
        {:&, _, [{:/, _, [{fun, meta, _}, idx]}]},
        acc,
        type,
        module
      ) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_strict_aliased_funs_of_type(fun_cap, acc, type, module)
  end

  def get_strict_aliased_funs_of_type(ast, acc, _type, _module) do
    {ast, acc}
  end

  def get_aliased_funs_of_type(
        {{:., _, [{:__aliases__, _, aliases}, type]}, _, _opts} = ast,
        acc,
        type,
        module
      ) do
    if alias_matches?(ast, aliases, module) do
      {ast, [ast | acc]}
    else
      {ast, acc}
    end
  end

  def get_aliased_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type, module) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_aliased_funs_of_type(fun_cap, acc, type, module)
  end

  def get_aliased_funs_of_type(ast, acc, _type, _module) do
    {ast, acc}
  end

  defp alias_matches?(ast, aliases, target) do
    if Sobelow.Lexical.active?() do
      case Sobelow.Lexical.matches?(ast, target) do
        nil -> legacy_alias_match?(aliases, target)
        matched? -> matched?
      end
    else
      legacy_alias_match?(aliases, target)
    end
  end

  defp legacy_alias_match?(aliases, target) do
    if is_list(target), do: aliases == target, else: List.last(aliases) == target
  end

  def get_piped_aliased_funs_of_type(ast, type, module) when is_list(module) do
    case ast do
      {{:., _, [{:__aliases__, _, aliases}, ^type]}, _, _} ->
        if alias_matches?(ast, aliases, module), do: [ast], else: []

      _ ->
        []
    end
  end

  def get_piped_aliased_funs_of_type(ast, type, module) do
    case ast do
      {{:., _, [{:__aliases__, _, aliases}, ^type]}, _, _} ->
        if alias_matches?(ast, aliases, module) do
          [ast]
        else
          []
        end

      _ ->
        []
    end
  end

  def get_top_level_funs_of_type(ast, type) do
    {_, acc} = Macro.prewalk(ast, [], &get_top_level_funs_of_type(&1, &2, type))
    acc
  end

  def get_top_level_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_top_level_funs_of_type(fun_cap, acc, type)
  end

  def get_top_level_funs_of_type({type, _, _} = ast, acc, type) do
    {[], [ast | acc]}
  end

  def get_top_level_funs_of_type(ast, acc, _type) do
    {ast, acc}
  end

  def get_funs_of_type(ast, type) do
    indexed_funs(ast, :bare, type, &get_funs_of_type(&1, &2, type))
  end

  defp indexed_funs(ast, kind, type, matcher) do
    case Sobelow.FunctionAnalysis.candidates(ast, kind, type) do
      {:ok, nodes} ->
        Enum.filter(nodes, fn node -> elem(matcher.(node, []), 1) != [] end)

      :error ->
        {_, acc} = Macro.prewalk(ast, [], matcher)
        acc
    end
  end

  # This should not effect piped, aliased, etc get_funs* functions.
  def get_funs_of_type({name, _, opts}, acc, type) when name in [:def, :defp, :defmacro] do
    case Macro.prewalk(opts, [], &get_do_block/2) do
      {_, [[{:do, block}]]} ->
        get_funs_of_type(block, acc, type)

      _ ->
        {[], acc}
    end
  end

  def get_funs_of_type({type, _, _} = ast, acc, types) when is_list(types) do
    if Enum.member?(types, type) do
      {ast, [ast | acc]}
    else
      {ast, acc}
    end
  end

  def get_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_funs_of_type(fun_cap, acc, type)
  end

  def get_funs_of_type({type, _, _} = ast, acc, type) do
    {ast, [ast | acc]}
  end

  def get_funs_of_type(ast, acc, _type), do: {ast, acc}

  def get_piped_funs_of_type(ast, type) do
    case ast do
      {^type, _, _} ->
        [ast]

      _ ->
        []
    end
  end

  @doc false
  def create_fun_cap(fun, meta, idx) when is_number(idx) and idx > 0 do
    opts = Enum.map(1..trunc(idx), fn i -> {:&, [], [i]} end)
    {fun, meta, opts}
  end

  def create_fun_cap(fun, meta, _) do
    {fun, meta, [{:&, [], []}]}
  end

  def get_pipe_funs(ast) do
    Sobelow.FunctionAnalysis.fetch(ast, :pipes, fn ->
      ast
      |> get_funs_of_type(:|>)
      |> Enum.filter(fn pipe ->
        {_, acc} = Macro.prewalk(pipe, [], &get_do_block/2)
        Enum.empty?(acc)
      end)
    end)
  end

  def get_do_block({:|>, _, [_, {_, _, [[do: _block]]}]} = ast, acc) do
    {[], [ast | acc]}
  end

  def get_do_block([do: _block] = ast, acc), do: {[], [ast | acc]}
  def get_do_block(ast, acc), do: {ast, acc}

  def extract_opts({:send_resp, _, nil}), do: []
  def extract_opts({:send_resp, _, opts}), do: parse_opts(List.last(opts))

  def extract_opts({{:., _, _}, _, _opts} = fun) do
    parse_opts(fun)
  end

  def extract_opts({:<<>>, _, opts}) do
    opts
    |> Enum.map(&parse_string_interpolation/1)
  end

  def extract_opts({val, _, nil}), do: [val]
  def extract_opts({val, _, []}), do: [val]

  def extract_opts({_, _, opts}) when is_list(opts) do
    opts
    |> Enum.map(&parse_opts/1)
  end

  def extract_opts(opts) when is_list(opts), do: Enum.map(opts, &parse_opts/1)
  def extract_opts(_), do: []
  # A more general extract_opts. May be able to replace some of the
  # function specific extractions.
  def extract_opts({_, _, nil}, _idx), do: []

  def extract_opts({_, _, opts}, idx) do
    parse_opts(Enum.at(opts, idx))
  end

  defp parse_opts({:@, _, _}), do: []
  defp parse_opts({key, _, nil}), do: key

  defp parse_opts({:<<>>, _, opts}) do
    Enum.map(opts, &parse_string_interpolation/1)
    |> List.flatten()
  end

  defp parse_opts({{:., _, [Access, :get]}, _, [{{:., _, [{:conn, _, nil}, :params]}, _, _}, _]}) do
    "conn.params"
  end

  defp parse_opts({{:., _, [Access, :get]}, _, opts}) do
    [{val, _, _} | _] = opts
    val
  end

  defp parse_opts({{:., _, _}, _, [{:var!, _, [{:assigns, _, EEx.Engine}]}, var]}) do
    "@#{var}"
  end

  defp parse_opts({{:., _, [{:__aliases__, _, module}, _func]}, _, _}) do
    Module.concat(module)
  end

  # This is what an accessor func looks like, eg conn.params
  defp parse_opts({{:., _, [{val, _, nil}, _]}, _, _}), do: val
  defp parse_opts({:., _, [{val, _, nil}, _]}), do: val

  defp parse_opts({{:., _, opts}, _, _} = _fun) do
    parse_opts(opts)
  end

  defp parse_opts({:&, _, [i]} = cap) when is_integer(i), do: Macro.to_string(cap)

  defp parse_opts({fun, _, opts}) when fun in @operators do
    Enum.map(opts, &parse_opts/1)
  end

  # Sigils aren't ordinary function calls.
  defp parse_opts({fun, _, _}) when fun in [:sigil_s, :sigil_e], do: []
  defp parse_opts({fun, _, opts}) when is_list(opts), do: fun
  defp parse_opts(opts) when is_tuple(opts), do: parse_opts(Tuple.to_list(opts))
  defp parse_opts(opts) when is_list(opts), do: Enum.map(opts, &parse_opts/1)
  defp parse_opts(_), do: []

  def get_fun_declaration(ast) do
    Sobelow.FunctionAnalysis.fetch(ast, :declaration, fn -> do_get_fun_declaration(ast) end)
  end

  defp do_get_fun_declaration({_, _, fun_opts}) do
    [definition | _] = fun_opts

    declaration =
      case definition do
        {:when, _, [opts | _]} -> opts
        opts -> opts
      end

    params = get_params(declaration)
    {fun_name, _, _} = declaration

    {params, {fun_name, get_fun_line(declaration)}}
  end

  defp do_get_fun_declaration(_) do
    {[], {"", ""}}
  end

  ## Get function parameters.
  defp get_params({_, _, params}) when is_list(params) do
    Enum.flat_map(params, &get_params/1)
  end

  defp get_params({_, params}) when is_tuple(params) do
    get_params(params)
  end

  defp get_params({var, _, nil}), do: [var]
  defp get_params(_), do: []

  def get_pipe_val(ast, pipe_fun) do
    Sobelow.FunctionAnalysis.fetch(ast, {:pipe_value, pipe_fun}, fn ->
      {_, acc} = Macro.prewalk(ast, [], &get_pipe_val(&1, &2, pipe_fun))
      acc
    end)
  end

  def get_pipe_val({:|>, _, [{:|>, _, opts}, pipefun]}, acc, pipefun) do
    key = extract_opts(List.last(opts))
    {[], [key | acc]}
  end

  def get_pipe_val({:|>, _, [opts, pipefun]}, acc, pipefun) do
    key = extract_opts(opts)
    {[], [key | acc]}
  end

  def get_pipe_val({:|>, _, [{fun, _, funopts} = opts, maybe_pipe]} = ast, acc, pipe)
      when fun not in [:|>] do
    {_, match_pipe} = Macro.prewalk(maybe_pipe, [], &get_match(&1, &2, pipe))
    {_, match_opts} = Macro.prewalk(opts, [], &get_match(&1, &2, pipe))

    cond do
      !Enum.empty?(match_pipe) ->
        {maybe_pipe, acc}

      !Enum.empty?(match_opts) ->
        key = extract_opts(funopts)
        {[], [key | acc]}

      true ->
        {ast, acc}
    end
  end

  def get_pipe_val(ast, acc, _pipe), do: {ast, acc}

  defp get_match(match, acc, match), do: {[], [match | acc]}
  defp get_match(ast, acc, _), do: {ast, acc}

  defp parse_string_interpolation({key, _, nil}), do: key

  defp parse_string_interpolation({:"::", _, opts}) do
    parse_string_interpolation(opts)
  end

  defp parse_string_interpolation([{{:., _, [Kernel, :to_string]}, _, vars}, _]) do
    Enum.map(vars, &parse_opts/1)
  end

  defp parse_string_interpolation({{:., _, [Kernel, :to_string]}, _, opts}) do
    Enum.map(opts, &parse_opts/1)
  end

  defp parse_string_interpolation({:<<>>, _, opts}) do
    opts
    |> Enum.map(&parse_string_interpolation/1)
  end

  defp parse_string_interpolation(_) do
    []
  end

  def get_fun_line({_, meta, _}) when is_list(meta) do
    Keyword.get(meta, :line, 0)
  end

  def get_fun_column({_, meta, _}) when is_list(meta) do
    Keyword.get(meta, :column, 0)
  end

  # XSS Utils

  def get_template_vars(raw_funs) do
    Enum.flat_map(raw_funs, fn ast ->
      {vars, _, _} = get_fun_vars_and_meta([ast], 0, :raw, :HTML)

      Enum.flat_map(vars, fn {_, var} ->
        var
      end)
    end)
  end

  def parse_render_opts({:render, _, opts}, params, idx) do
    {_, vars} = Macro.prewalk(opts, [], &extract_render_opts/2)

    template = if is_nil(opts) || Enum.empty?(opts), do: "", else: Enum.at(opts, idx)

    reflected_vars =
      Enum.filter(vars, fn var ->
        (reflected_var?(var) && in_params?(var, params)) || conn_params?(var)
      end)

    var_keys =
      Enum.map(vars, fn {key, val} ->
        case val do
          {_, _, _} -> key
          _ -> nil
        end
      end)

    reflected_var_keys = Keyword.keys(reflected_vars)

    {template, reflected_var_keys, var_keys -- reflected_var_keys}
  end

  def extract_render_opts(ast, acc) do
    if Keyword.keyword?(ast) do
      {ast, ast}
    else
      {ast, acc}
    end
  end

  defp reflected_var?({_, {_, _, nil}}), do: true
  defp reflected_var?(_), do: false

  defp in_params?({_, {var, _, _}}, params) do
    Enum.member?(params, var)
  end

  def conn_params?({_, {{:., _, [Access, :get]}, _, access_opts}}),
    do: conn_params?(access_opts)

  def conn_params?([{{:., _, [{:conn, _, nil}, :params]}, _, []}, _]), do: true
  def conn_params?(_), do: false
end
