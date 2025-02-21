#!/usr/bin/env python3
import os
import sys
import shutil
import yaml
import argparse
import re
import subprocess

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

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="ThreatStalker: Track and detect attackers using multiple rules"
    )
    parser.add_argument(
        '--attackID', '-id', nargs='+', required=True,
        help="MITRE ATT&CK technique ID(s) (e.g., t1190, t1505)"
    )
    parser.add_argument(
        '--product', '-p', required=True,
        help="Product (e.g., windows)"
    )
    # Option to decide whether to execute the hunting tool hayabusa
    parser.add_argument(
        '--use-hayabusa', action='store_true',
        help="If set, the hunting tool hayabusa will be executed after processing."
    )
    # Mutually exclusive group for specifying the .evtx file using -d or -f (not required by default)
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-d", dest="d_evtx", help="Path to the .evtx file using -d option"
    )
    group.add_argument(
        "-f", dest="f_evtx", help="Path to the .evtx file using -f option"
    )
    return parser.parse_args()

def clean_chainrule_directory(chainrule_dir):
    """
    Delete the 'chainrule' directory if it exists and create a new one.
    """
    if os.path.exists(chainrule_dir):
        shutil.rmtree(chainrule_dir)
    os.makedirs(chainrule_dir)

def process_sigma_files(sigma_dir, chainrule_dir, attack_ids, product):
    """
    From the specified subdirectories within the sigma directory, copy YAML files
    that match the given attackIDs and product to the chainrule directory, organized by tactic.
    """
    subdirs = ["rules", "rules-threat-hunting"]
    tactic_to_files = {}
    unique_matched_files = set()
    technique_pattern = re.compile(r"^attack\.t\d+(\.\d+)?$", re.IGNORECASE)

    for sub in subdirs:
        sub_dir_path = os.path.join(sigma_dir, sub)
        if not os.path.exists(sub_dir_path):
            print(f"Error: '{sub_dir_path}' directory does not exist.")
            continue

        for root, dirs, files in os.walk(sub_dir_path):
            for file in files:
                if file.endswith(".yml"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            data = yaml.safe_load(f)
                    except Exception as e:
                        print(f"Error reading file {file_path}: {e}")
                        continue

                    # Check that 'tags' exists and is a list
                    if "tags" not in data or not isinstance(data["tags"], list):
                        continue
                    tags = data["tags"]

                    # Check for the presence of technique tags matching the specified attackIDs
                    technique_match = False
                    for tag in tags:
                        if isinstance(tag, str) and tag.startswith("attack."):
                            if technique_pattern.match(tag):
                                tech = tag[len("attack."):].lower()
                                for aid in attack_ids:
                                    if tech.startswith(aid):
                                        technique_match = True
                                        break
                        if technique_match:
                            break
                    if not technique_match:
                        continue

                    # Check the product in the logsource field
                    product_match = False
                    if "logsource" in data:
                        if "product" in data["logsource"]:
                            prod_field = data["logsource"]["product"]
                            if isinstance(prod_field, list):
                                for prod in prod_field:
                                    if isinstance(prod, str) and prod.lower() == product:
                                        product_match = True
                                        break
                            elif isinstance(prod_field, str):
                                if prod_field.lower() == product:
                                    product_match = True
                    if not product_match:
                        continue

                    # Extract tactic tags (attack. tags that are not technique tags)
                    tactic_tags = []
                    for tag in tags:
                        if isinstance(tag, str) and tag.startswith("attack."):
                            if not technique_pattern.match(tag):
                                tactic = tag[len("attack."):].lower()
                                tactic_tags.append(tactic)
                    # If no tactic tag is found, use "misc" as default
                    if not tactic_tags:
                        tactic_tags = ["misc"]

                    unique_matched_files.add(file_path)

                    # Copy the file for each tactic
                    for tactic in tactic_tags:
                        tactic_dir = os.path.join(chainrule_dir, tactic)
                        os.makedirs(tactic_dir, exist_ok=True)
                        dst = os.path.join(tactic_dir, os.path.basename(file_path))
                        try:
                            shutil.copy2(file_path, dst)
                            if tactic not in tactic_to_files:
                                tactic_to_files[tactic] = set()
                            tactic_to_files[tactic].add(file_path)
                        except Exception as e:
                            print(f"Error copying file {file_path}: {e}")

    return tactic_to_files, unique_matched_files

def print_summary(tactic_to_files, unique_matched_files):
    """Print a summary of the number of files per tactic and total unique rules."""
    print("\nMITRE Tactic:\n")
    for tactic, files_set in tactic_to_files.items():
        print(f"{tactic}: {len(files_set)} files")
    print(f"\nTotal unique rules : {len(unique_matched_files)}\n\n")

def run_hayabusa_command(evtx_flag=None, evtx_file=None):
    """Execute the hayabusa command with optional evtx file parameter."""
    cmd = ["hayabusa", "csv-timeline", "--no-wizard", "--quiet", "--rules", "chainrule"]
    # Append the evtx file option if provided
    if evtx_flag and evtx_file:
        cmd.extend([evtx_flag, evtx_file])
    try:
        subprocess.run(cmd, check=True)
    except Exception as e:
        print(f"Error running hayabusa command: {e}")

def main():
    print_logo()
    args = parse_args()

    # If hayabusa is to be used, ensure that either -d or -f is specified
    if args.use_hayabusa:
        if not (args.d_evtx or args.f_evtx):
            sys.exit("Error: When using hayabusa, either -d or -f must be specified.")

    # Normalize input values to lowercase for attackIDs and product
    attack_ids = [aid.lower() for aid in args.attackID]
    product = args.product.lower()

    # Determine evtx parameters if hayabusa is enabled
    evtx_flag = None
    evtx_file = None
    if args.use_hayabusa:
        if args.d_evtx:
            evtx_flag = "-d"
            evtx_file = args.d_evtx
        elif args.f_evtx:
            evtx_flag = "-f"
            evtx_file = args.f_evtx

    current_dir = os.getcwd()
    sigma_dir = os.path.join(current_dir, "sigma")
    if not os.path.exists(sigma_dir):
        print(f"Error: '{sigma_dir}' directory does not exist.")
        sys.exit(1)

    # Delete and recreate the 'chainrule' directory each time
    chainrule_dir = os.path.join(current_dir, "chainrule")
    clean_chainrule_directory(chainrule_dir)

    # Extract sigma rules and copy them to the chainrule directory
    tactic_to_files, unique_matched_files = process_sigma_files(
        sigma_dir, chainrule_dir, attack_ids, product
    )

    print_summary(tactic_to_files, unique_matched_files)

    # Execute the hayabusa command only if the --use-hayabusa flag is set
    if args.use_hayabusa:
        run_hayabusa_command(evtx_flag, evtx_file)

if __name__ == '__main__':
    main()
