#!/usr/bin/env python3
import os
import sys
import shutil
import yaml
import argparse
import re
import subprocess
import json
from mitreattack.stix20 import MitreAttackData

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
    # Mutually exclusive group for specifying either ATT&CK technique ID(s) or Threat Actor Name
    group_att = parser.add_mutually_exclusive_group(required=True)
    group_att.add_argument(
        '--attackID', '-id', nargs='+',
        help="MITRE ATT&CK technique ID(s) (e.g., t1190, t1505)"
    )
    group_att.add_argument(
        '--threat_actor_name', '-a',
        help="Threat Actor Name (e.g., APT29)"
    )
    parser.add_argument(
        '--product', '-p', required=True,
        help="Product (e.g., windows)"
    )
    # Option to execute hayabusa hunting tool after processing
    parser.add_argument(
        '--use-hayabusa', action='store_true',
        help="If set, execute the hayabusa hunting tool after processing."
    )
    # Mutually exclusive group for specifying the .evtx file using -d or -f
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
    If the chainrule directory exists, remove it and recreate a new one.
    """
    if os.path.exists(chainrule_dir):
        shutil.rmtree(chainrule_dir)
    os.makedirs(chainrule_dir)

def process_sigma_files(sigma_dir, chainrule_dir, attack_ids, product):
    """
    From specified subdirectories within the sigma directory, copy YAML files
    that match the given attackIDs and product to the chainrule directory, organized by tactic.
    
    Note: attack tags like 'attack.sNNNN' or 'attack.gNNNN' are ignored.
    """
    subdirs = ["builtin"]
    tactic_to_files = {}
    unique_matched_files = set()
    technique_pattern = re.compile(r"^attack\.t\d+(\.\d+)?$", re.IGNORECASE)
    ignore_pattern = re.compile(r"^attack\.[sg]\d+$", re.IGNORECASE)

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

                    if "tags" not in data or not isinstance(data["tags"], list):
                        continue
                    tags = data["tags"]

                    # Check if any tag matches the specified attackIDs (ignoring attack.s/g tags)
                    technique_match = False
                    for tag in tags:
                        if isinstance(tag, str) and tag.startswith("attack."):
                            if ignore_pattern.match(tag):
                                continue
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

                    # Check that the logsource product field matches the specified product
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
                            if ignore_pattern.match(tag):
                                continue
                            if not technique_pattern.match(tag):
                                tactic = tag[len("attack."):].lower()
                                tactic_tags.append(tactic)
                    if not tactic_tags:
                        tactic_tags = ["misc"]

                    unique_matched_files.add(file_path)

                    # Copy the file for each tactic category
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
    print("\nMITRE Tactic Summary:\n")
    for tactic, files_set in tactic_to_files.items():
        print(f"{tactic}: {len(files_set)} files")
    print(f"\nTotal unique rules: {len(unique_matched_files)}\n\n")

def run_hayabusa_command(evtx_flag=None, evtx_file=None):
    """Execute the hayabusa command with an optional evtx file parameter."""
    cmd = ["hayabusa", "csv-timeline", "--no-wizard", "--quiet", "--rules", "chainrule"]
    if evtx_flag and evtx_file:
        cmd.extend([evtx_flag, evtx_file])
    try:
        print("\n\nExecuting hayabusa...\n\n")
        subprocess.run(cmd, check=True)
    except Exception as e:
        print(f"Error running hayabusa command: {e}")

def get_group_stix_id_by_name(stix_file, group_name):
    """
    Load the local STIX file and return the STIX ID of the specified threat actor (intrusion-set object).
    """
    try:
        with open(stix_file, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        print(f"Error: Failed to read STIX file: {e}")
        return None

    for obj in bundle.get("objects", []):
        if obj.get("type") == "intrusion-set" and obj.get("name", "").lower() == group_name.lower():
            return obj.get("id")
    return None

def get_attack_ids_by_threat_actor(stix_file, threat_actor_name):
    """
    From the specified threat actor name, obtain the STIX ID and use MitreAttackData to return a list of
    ATT&CK technique IDs (e.g., t1190) used by the group.
    """
    group_stix_id = get_group_stix_id_by_name(stix_file, threat_actor_name)
    if group_stix_id is None:
        print(f"Threat actor '{threat_actor_name}' not found in the STIX data.")
        return None
    mitre_attack_data = MitreAttackData(stix_file)
    techniques_used = mitre_attack_data.get_techniques_used_by_group(group_stix_id)
    attack_ids = []
    print(f"{threat_actor_name} uses {len(techniques_used)} technique(s):")
    for t in techniques_used:
        technique = t["object"]
        attack_id = mitre_attack_data.get_attack_id(technique.id)
        attack_ids.append(attack_id.lower())
        print(f"* {technique.name} ({attack_id})")
    return attack_ids

def main():
    print_logo()
    args = parse_args()

    # If hayabusa is to be used, ensure that either -d or -f is specified
    if args.use_hayabusa:
        if not (args.d_evtx or args.f_evtx):
            sys.exit("Error: When using hayabusa, either -d or -f must be specified.")

    product = args.product.lower()

    # If threat actor name is specified, get technique IDs from the STIX file
    if args.threat_actor_name:
        stix_file = "./mitre_data/enterprise-attack.json"  # Path to the local STIX file
        attack_ids = get_attack_ids_by_threat_actor(stix_file, args.threat_actor_name)
        if not attack_ids:
            sys.exit(1)
    else:
        attack_ids = [aid.lower() for aid in args.attackID]

    current_dir = os.getcwd()
    sigma_dir = os.path.join(current_dir, "hayabusa-rules/sigma")
    if not os.path.exists(sigma_dir):
        print(f"Error: '{sigma_dir}' directory does not exist.")
        sys.exit(1)

    # Clean up and recreate the 'chainrule' directory
    chainrule_dir = os.path.join(current_dir, "chainrule")
    clean_chainrule_directory(chainrule_dir)

    # Process sigma rules and copy matching files to the chainrule directory
    tactic_to_files, unique_matched_files = process_sigma_files(
        sigma_dir, chainrule_dir, attack_ids, product
    )
    print_summary(tactic_to_files, unique_matched_files)
    
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
