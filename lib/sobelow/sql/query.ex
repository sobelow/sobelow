defmodule Sobelow.SQL.Query do
  @moduledoc """
  # SQL Injection in Query

  This submodule of the `SQL` module checks for SQL injection
  vulnerabilities through usage of the `Ecto.Adapters.SQL.query`
  and `Ecto.Adapters.SQL.query!`.

  Ensure that the query is parameterized and not user-controlled.

  Calls are matched when they are qualified — `Repo.query(sql)` or
  `Ecto.Adapters.SQL.query(Repo, sql, [])`. A bare `query(...)` is only treated
  as Ecto's in a file that has `import Ecto.Adapters.SQL` or `use Ecto.Repo`,
  since otherwise the name almost always belongs to a function of the project's
  own.

  SQLi Query checks can be ignored with the following command:

      $ mix sobelow -i SQL.Query
  """
  @uid 17
  @finding_type "SQL.Query: SQL injection"
  @query_funcs [:query, :query!]

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Enum.each(@query_funcs, fn query_func ->
      Finding.init(@finding_type, meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, parse_sql_def(fun, query_func, meta_file.imports_ecto_sql?))
      |> Enum.each(&Print.add_finding(&1))
    end)

    Enum.each(@query_funcs, fn query_func ->
      Finding.init(@finding_type, meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, parse_repo_query_def(fun, query_func, meta_file.ecto_repo?))
      |> Enum.each(&Print.add_finding(&1))
    end)
  end

  ## query(repo, sql, params \\ [], opts \\ [])
  def parse_sql_def(fun, type, unqualified? \\ false) do
    Parse.get_fun_vars_and_meta(fun, 1, type, module(:SQL, unqualified?))
  end

  def parse_repo_query_def(fun, type, unqualified? \\ false) do
    Parse.get_fun_vars_and_meta(fun, 0, type, module(:Repo, unqualified?))
  end

  # `query`/`query!` are common names. Matching them unqualified flags every
  # local function that happens to be called one, so it is only done for a file
  # that imported `Ecto.Adapters.SQL` or is itself an `Ecto.Repo` — the two ways
  # the bare name can reach Ecto. Everywhere else the call must be qualified.
  defp module(module, true), do: module
  defp module(module, false), do: {:required, module}
end
