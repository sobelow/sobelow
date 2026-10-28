defmodule Sobelow.Config.TLSOptions do
  @moduledoc false

  alias Sobelow.{Finding, Lexical, Parse, Print, Utils}

  def run(check, type, dir_path, configs, files) do
    Enum.each(configs, &scan_file(check, type, Path.join(dir_path, &1), MapSet.new()))

    Enum.each(files, fn file ->
      # Discovery has already warned about unreadable sources.
      if match?({:ok, _}, Sobelow.Scan.source(file.file_path)) do
        scan_file(check, type, file.file_path, skipped_functions(file, check))
      end
    end)
  end

  defp scan_file(check, type, path, skipped) do
    ast = Parse.ast(path)

    Lexical.with_context(Lexical.file_calls(ast), fn ->
      ast
      |> check.parse_def(skipped)
      |> Enum.each(&add_finding(type, path, &1))
    end)
  end

  defp add_finding(type, path, {call, confidence}) do
    finding = %{
      Finding.init(type, Utils.normalize_path(path), confidence)
      | vuln_source: call,
        vuln_line_no: Parse.get_fun_line(call),
        vuln_col_no: Parse.get_fun_column(call),
        fun_source: call
    }

    Print.add_finding(finding)
  end

  defp skipped_functions(file, check) do
    for context <- file.scan_contexts,
        {{fun, skips}, _lexical} <- context.functions,
        Sobelow.get_env(:skip),
        Enum.any?(skips, &(Sobelow.get_mod(&1) in [check, Sobelow.Config])),
        into: MapSet.new(),
        do: fun
  end
end
