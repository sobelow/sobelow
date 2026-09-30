defmodule Sobelow.Parse do
  @moduledoc false

  # Compatibility entry points. Keep traversal callbacks and default arities
  # callable here; implementations live beside the AST responsibility they serve.

  alias Sobelow.Parse.Calls
  alias Sobelow.Parse.Metadata
  alias Sobelow.Parse.Source
  alias Sobelow.Parse.Template
  alias Sobelow.Parse.Variables

  # Source loading and diagnostics.
  defdelegate ast(filepath), to: Source
  defdelegate ast_with_skip_warnings(filepath), to: Source
  defdelegate format_error(error, token), to: Source
  defdelegate format_location(location), to: Source

  # Definitions, module scopes and pipeline skips.
  defdelegate get_meta_funs(ast), to: Metadata
  defdelegate get_meta_funs(ast, acc), to: Metadata
  defdelegate get_module_meta_funs(ast), to: Metadata
  defdelegate file_metadata(ast), to: Metadata
  defdelegate get_pipelines_with_skips(ast), to: Metadata

  # EEx/HEEx expressions and controller render assignments.
  defdelegate get_meta_template_funs(filepath), to: Template
  defdelegate get_meta_template_fun(ast), to: Template
  defdelegate get_meta_template_fun(ast, acc), to: Template
  defdelegate get_heex_raw_funs(ast, file \\ "inline HEEx"), to: Template
  defdelegate get_template_vars(raw_funs), to: Template
  defdelegate parse_render_opts(ast, params, idx), to: Template
  defdelegate extract_render_opts(ast, acc), to: Template
  defdelegate conn_params?(ast), to: Template

  # Bare, qualified, captured and piped function calls.
  defdelegate get_fun_vars_and_meta(fun, idx, type, module), to: Calls
  defdelegate get_erlang_fun_vars_and_meta(fun, idx, type, module), to: Calls
  defdelegate get_erlang_funs_from_pipe(fun, type, module), to: Calls
  defdelegate get_erlang_funs_of_type(ast, type), to: Calls
  defdelegate get_erlang_funs_of_type(ast, acc, type, module), to: Calls
  defdelegate get_erlang_aliased_funs_of_type(ast, type, module), to: Calls
  defdelegate get_piped_erlang_aliased_funs_of_type(ast, type, module), to: Calls
  defdelegate get_funs_by_module(ast, module), to: Calls
  defdelegate get_assigns_from(fun, module), to: Calls
  defdelegate get_aliased_funs_of_type(ast, type, module), to: Calls
  defdelegate get_aliased_funs_of_type(ast, acc, type, module), to: Calls
  defdelegate get_strict_aliased_funs_of_type(ast, acc, type, module), to: Calls
  defdelegate get_piped_aliased_funs_of_type(ast, type, module), to: Calls
  defdelegate get_top_level_funs_of_type(ast, type), to: Calls
  defdelegate get_top_level_funs_of_type(ast, acc, type), to: Calls
  defdelegate get_funs_of_type(ast, type), to: Calls
  defdelegate get_funs_of_type(ast, acc, type), to: Calls
  defdelegate get_piped_funs_of_type(ast, type), to: Calls
  defdelegate create_fun_cap(fun, meta, arity), to: Calls
  defdelegate get_pipe_funs(ast), to: Calls
  defdelegate get_do_block(ast, acc), to: Calls

  # Tainted arguments, parameters and source locations.
  defdelegate normalize_finding(finding), to: Variables
  defdelegate extract_opts(ast), to: Variables
  defdelegate extract_opts(ast, idx), to: Variables
  defdelegate get_fun_declaration(ast), to: Variables
  defdelegate get_pipe_val(ast, pipe_fun), to: Variables
  defdelegate get_pipe_val(ast, acc, pipe_fun), to: Variables
  defdelegate get_fun_line(ast), to: Variables
  defdelegate get_fun_column(ast), to: Variables
end
