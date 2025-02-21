#!/usr/bin/env python3
import os
import sys
from args import parse_args
from sigma_processor import clean_chainrule_directory, process_sigma_files, print_summary
from hayabusa_runner import run_hayabusa_command
from stix_utils import get_attack_ids_by_threat_actor

def print_logo():
    logo = """
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗   ███████╗████████╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗ 
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝   ██╔════╝╚══██╔══╝██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
   ██║   ███████║██████╔╝█████╗  ███████║   ██║      ███████╗   ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║      ╚════██║   ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║      ███████║   ██║   ██║  ██║███████╗██║  ██╗███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝      ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

    Tracking and detecting attackers using multiple sigma rules
    """
    print(logo)

def main():
    print_logo()
    args = parse_args()

    # When hayabusa is used, ensure that either -d or -f is specified
    if args.use_hayabusa:
        if not (args.d_evtx or args.f_evtx):
            sys.exit("Error: When using hayabusa, either -d or -f must be specified.")

    product = args.product.lower()
    # tacticsは存在すれば小文字に変換
    tactic_filter = args.tactics.lower() if args.tactics else None

    # 以下、必ず threat_actor_name or attackID or tactics のいずれかが指定される前提
    if args.threat_actor_name:
        stix_file = "./mitre_data/enterprise-attack.json"  # Path to the local STIX file
        attack_ids = get_attack_ids_by_threat_actor(stix_file, args.threat_actor_name)
        if not attack_ids:
            sys.exit(1)
    elif args.attackID:
        attack_ids = [aid.lower() for aid in args.attackID]
    else:
        # tacticsのみの場合は、攻撃IDフィルタはバイパス
        attack_ids = []

    current_dir = os.getcwd()
    sigma_dir = os.path.join(current_dir, "hayabusa-rules", "sigma")
    if not os.path.exists(sigma_dir):
        print(f"Error: '{sigma_dir}' directory does not exist.")
        sys.exit(1)

    # Clean up and recreate the 'chainrule' directory
    chainrule_dir = os.path.join(current_dir, "chainrule")
    clean_chainrule_directory(chainrule_dir)

    # Process sigma rules and copy matching files to the chainrule directory.
    # --tacticsが指定された場合は、tacticsに一致するフォルダのみ作成
    tactic_to_files, unique_matched_files = process_sigma_files(
        sigma_dir, chainrule_dir, attack_ids, product, tactic_filter
    )
    print_summary(tactic_to_files, unique_matched_files, tactic_filter)
    
    # Execute the hayabusa command if the --use-hayabusa flag is set
    if args.use_hayabusa:
        evtx_flag = None
        evtx_file = None
        if args.d_evtx:
            evtx_flag = "-d"
            evtx_file = args.d_evtx
        elif args.f_evtx:
            evtx_flag = "-f"
            evtx_file = args.f_evtx
        run_hayabusa_command(evtx_flag, evtx_file)

if __name__ == '__main__':
    main()
