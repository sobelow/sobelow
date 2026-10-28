defmodule Sobelow.LockfileFallbackTest do
  use Sobelow.ScanCase, async: false

  setup %{tmp_dir: root} do
    File.mkdir_p!(Path.join(root, "lib"))

    File.write!(Path.join(root, "mix.exs"), """
    defmodule Lockfile.MixProject do
      use Mix.Project
      def project, do: [app: :lockfile_example, version: "0.1.0"]
    end
    """)

    File.write!(
      Path.join(root, "lib/example.ex"),
      "defmodule Example do\n  def run, do: :ok\nend\n"
    )

    {:ok, root: root, lockfile: Path.join(root, "mix.lock")}
  end

  @tag :tmp_dir
  test "Mix-written atom keys produce advisory findings without installed dependencies or warnings",
       %{root: root, lockfile: path} do
    refute File.dir?(Path.join(root, "deps"))

    File.write!(path, ~S'''
    %{
      "coherence": {:hex, :coherence, "0.5.1", "checksum", [:mix], [], "hexpm", "checksum"},
      "ash": {:hex, :ash, "1.0.0", "checksum", [:mix], [], "hexpm", "checksum"}
    }
    ''')

    {stdout, stderr} = scan_root(root)
    expected_path = Sobelow.Utils.normalize_path(path)

    assert [%{"file" => ^expected_path, "cve" => "CVE-2018-20301"}] =
             stdout |> Jason.decode!() |> findings_for("Vuln.Coherence")

    assert stderr == ""
  end

  @tag :tmp_dir
  test "absent advisory packages stay quiet while falling back to a Mix-written lockfile",
       %{root: root, lockfile: path} do
    File.write!(path, ~S'''
    %{"ash": {:hex, :ash, "1.0.0", "checksum", [:mix], [], "hexpm", "checksum"}}
    ''')

    {stdout, stderr} = scan_root(root)

    assert [] ==
             stdout
             |> Jason.decode!()
             |> finding_modules()
             |> Enum.filter(&String.starts_with?(&1, "Vuln."))

    assert stderr == ""
  end

  defp scan_root(root) do
    stderr =
      ExUnit.CaptureIO.capture_io(:stderr, fn ->
        stdout =
          ExUnit.CaptureIO.capture_io(fn ->
            Mix.Tasks.Sobelow.run([
              "--root",
              root,
              "--private",
              "--no-router",
              "--format",
              "json",
              "--ignore",
              "XSS,SQL,Traversal,RCE,Misc,Config,CI,DOS"
            ])
          end)

        send(self(), {:lockfile_report, stdout})
      end)

    assert_receive {:lockfile_report, stdout}
    {stdout, stderr}
  end
end
