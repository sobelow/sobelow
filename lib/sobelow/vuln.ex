defmodule Sobelow.Vuln do
  @moduledoc """
  # Known Vulnerable Dependencies

  An application with known vulnerabilities is more easily subjected
  to automated or targeted attacks.

  If you wish to learn more about the specific vulnerabilities
  found within the Known Vulnerable Dependencies category, you may run the
  following commands to find out more:

            $ mix sobelow -d Vuln.PlugNull
            $ mix sobelow -d Vuln.CookieRCE
            $ mix sobelow -d Vuln.HeaderInject
            $ mix sobelow -d Vuln.Redirect
            $ mix sobelow -d Vuln.Coherence
            $ mix sobelow -d Vuln.Ecto

  Known Vulnerable checks of all types can be ignored with the following command:

      $ mix sobelow -i Vuln
  """
  @submodules [
    Sobelow.Vuln.PlugNull,
    Sobelow.Vuln.CookieRCE,
    Sobelow.Vuln.HeaderInject,
    Sobelow.Vuln.Redirect,
    Sobelow.Vuln.Coherence,
    Sobelow.Vuln.Ecto
  ]

  alias Sobelow.{Finding, Print, Utils}
  use Sobelow.FindingType

  def get_vulns(root) do
    allowed = Sobelow.allowed_checks(__MODULE__, @submodules)

    Enum.each(allowed, fn mod ->
      apply(mod, :run, [root])
    end)
  end

  @doc false
  # Read only literal version metadata. Projects often have a committed lockfile
  # but no `deps/` tree (for example in source archives or CI before deps.get).
  # Parsing the lockfile as AST avoids executing code from the scanned project.
  def dependency_version(root, package) do
    Sobelow.Scan.fetch({:dependency_version, Path.expand(root), package}, fn ->
      read_dependency_version(root, package)
    end)
  end

  defp read_dependency_version(root, package) do
    mixfile = Path.join([root, "deps", package, "mix.exs"])

    case if(File.regular?(mixfile), do: Sobelow.Config.get_version(mixfile)) do
      version when is_binary(version) -> {mixfile, version}
      _ -> locked_version(root, package)
    end
  end

  defp locked_version(root, package) do
    lockfile = Path.join(root, "mix.lock")

    with {:ok, {:%{}, _, entries}} <-
           Sobelow.Scan.fetch({:lockfile, Path.expand(lockfile)}, fn ->
             with {:ok, source} <- Sobelow.Scan.source(lockfile),
                  do: Code.string_to_quoted(source, emit_warnings: false)
           end),
         {_name, {:{}, _, [:hex, hex_package, version | _]}} <-
           Enum.find(entries, &lock_entry?(&1, package)),
         true <- is_atom(hex_package) and Atom.to_string(hex_package) == package,
         true <- is_binary(version) do
      {lockfile, version}
    else
      _ -> nil
    end
  end

  # Mix writes `"plug": {...}`, whose keys parse as atoms rather than strings.
  defp lock_entry?({name, _}, package) when is_binary(name), do: name == package
  defp lock_entry?({name, _}, package) when is_atom(name), do: Atom.to_string(name) == package
  defp lock_entry?(_entry, _package), do: false

  def print_finding(file, vsn, package, detail, cve \\ "TBA", mod) do
    type = "Vuln.#{mod}: Known Vulnerable Dependency - #{package} v#{vsn}"

    finding =
      %Finding{
        type: type,
        filename: Utils.normalize_path(file),
        fun_source: nil,
        vuln_source: nil,
        vuln_line_no: 0,
        vuln_col_no: 0,
        confidence: :high
      }
      |> Finding.fetch_fingerprint()

    case Sobelow.format() do
      "json" ->
        json_finding = [
          type: finding.type,
          details: detail,
          file: finding.filename,
          cve: cve,
          line: 0
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(finding, [
          "Details: #{detail}",
          "File: #{finding.filename}",
          "CVE: #{cve}"
        ])

      "compact" ->
        Print.log_compact_finding(finding)

      "flycheck" ->
        Print.log_flycheck_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end

  def details do
    @moduledoc
  end
end
