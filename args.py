import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.text import Text

def display_help():
    console = Console()

    console.print(Text("ThreatStalker - Advanced Threat Hunting Tool", style="bold cyan underline"))

    table = Table(show_lines=True)
    table.add_column("Option", style="bold yellow", justify="left")
    table.add_column("Description", style="bold green")

    table.add_row("--attackID, -id", "MITRE ATT&CK technique ID(s) (e.g., t1190, t1505)")
    table.add_row("--threat_actor_name, -a", "Threat Actor Name (e.g., APT29) - extracts associated techniques from the MITRE STIX data. Please see MITRE ATT&CK Groups(https://attack.mitre.org/groups/)")
    table.add_row("--tactics, -t", "Filter sigma rules by tactic tag (e.g., initial-access)")
    table.add_row("--lolbin -l", "Enable advanced LOLBin detection filtering")
    table.add_row("--product, -p", "[bold red]Required[/bold red] - Target product/platform (e.g., windows)")
    table.add_row("--use-hayabusa", "Execute the hayabusa hunting tool after rule extraction")
    table.add_row("-d", "Path to the .evtx directory (used only with --use-hayabusa)")
    table.add_row("-f", "Path to the .evtx file (used only with --use-hayabusa)")

    console.print(table)
    console.print("[bold red]Note:[/bold red] One of --threat_actor_name, --attackID, --tactics, or --lolbin must be specified.\n")
    sys.exit(0)

def parse_args():
    # コマンドライン引数に -h または --help が含まれている場合は、リッチなヘルプを表示する
    if '-h' in sys.argv or '--help' in sys.argv:
        display_help()

    parser = argparse.ArgumentParser(add_help=False)  # 標準のヘルプを無効化

    group_att = parser.add_mutually_exclusive_group()
    group_att.add_argument('--attackID', '-id', nargs='+', help="MITRE ATT&CK technique ID(s) (e.g., t1190, t1505)")
    group_att.add_argument('--threat_actor_name', '-a', help="Threat Actor Name (e.g., APT29) - extracts associated techniques from the MITRE STIX data. Please see MITRE ATT&CK Groups(https://attack.mitre.org/groups/)")
    parser.add_argument('--tactics', '-t', help="Filter sigma rules by tactic tag (e.g., initial-access)")
    parser.add_argument('--lolbin', '-l', action='store_true', help="Enable advanced LOLBin detection filtering")
    parser.add_argument('--product', '-p', required=True, help="Target product/platform (e.g., windows)")
    parser.add_argument('--use-hayabusa', action='store_true', help="Execute the hayabusa hunting tool after rule extraction")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", dest="d_evtx", help="Path to the .evtx directory (used only with --use-hayabusa)")
    group.add_argument("-f", dest="f_evtx", help="Path to the .evtx file (used only with --use-hayabusa)")

    args = parser.parse_args()

    if not (args.threat_actor_name or args.attackID or args.tactics or args.lolbin):
        Console().print("[bold red]Error:[/bold red] One of --threat_actor_name, --attackID, --tactics, or --lolbin must be specified.\n", style="bold red")
        display_help()

    return args
