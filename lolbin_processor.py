import os
import yaml
import shutil
import re

def process_lolbin_files(chainrule_dir):
    """
    Process LOLBAS YAML files.
    """
    current_dir = os.getcwd()
    lolbas_dir = os.path.join(current_dir, "LOLBAS")
    if not os.path.exists(lolbas_dir):
        print(f"LOLBAS directory not found at: {lolbas_dir}")
        return

    extracted_filenames = set()

    # Walk through the LOLBAS directory recursively and process .yml files
    for root, dirs, files in os.walk(lolbas_dir):
        for file in files:
            if file.endswith(".yml"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
                    continue

                # Check if 'Detection' key exists and is a list
                if "Detection" in data and isinstance(data["Detection"], list):
                    for entry in data["Detection"]:
                        if isinstance(entry, dict) and "Sigma" in entry:
                            sigma_url = entry["Sigma"]
                            if sigma_url and isinstance(sigma_url, str):
                                filename = sigma_url.rstrip("/").split("/")[-1]
                                extracted_filenames.add(filename)


    if not extracted_filenames:
        print("No LOLBIN Sigma filenames extracted.")
        return

    # Search for extracted filenames in hayabusa-rules/sigma/builtin
    sigma_builtin_dir = os.path.join(current_dir, "hayabusa-rules", "sigma", "builtin")
    if not os.path.exists(sigma_builtin_dir):
        print(f"Directory not found: {sigma_builtin_dir}")
        return

    found_files = []
    for root, dirs, files in os.walk(sigma_builtin_dir):
        for file in files:
            if file in extracted_filenames:
                found_files.append(os.path.join(root, file))

    if not found_files:
        print("No matching LOLBIN files found in hayabusa-rules/sigma/builtin.")
        return

    # Copy all found files to the chainrule directory
    for file_path in found_files:
        dest = os.path.join(chainrule_dir, os.path.basename(file_path))
        try:
            shutil.copy2(file_path, dest)
        except Exception as e:
            print(f"Error copying file {file_path}: {e}")

    print(f"Total LOLBIN files : {len(found_files)}")

def print_lolbin_summary(chainrule_dir):
    """
    Read the YAML files in chainrule_dir, extract attack tactic tags,
    and print a summary in fixed order.
    """
    tactic_counts = {}
    unique_files = set()
    technique_pattern = re.compile(r"^attack\.t\d+(\.\d+)?$", re.IGNORECASE)
    ignore_pattern = re.compile(r"^attack\.[sg]\d+$", re.IGNORECASE)
    
    order = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact"
    ]
    
    for root, dirs, files in os.walk(chainrule_dir):
        for file in files:
            if file.endswith(".yml"):
                file_path = os.path.join(root, file)
                unique_files.add(file_path)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
                    continue
                if "tags" not in data or not isinstance(data["tags"], list):
                    continue
                tags = data["tags"]
                tactic_tags = []
                for tag in tags:
                    if isinstance(tag, str) and tag.startswith("attack."):
                        if ignore_pattern.match(tag):
                            continue
                        if technique_pattern.match(tag):
                            continue
                        tactic = tag[len("attack."):].lower()
                        tactic_tags.append(tactic)
                if not tactic_tags:
                    tactic_tags = ["misc"]
                for tactic in tactic_tags:
                    tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    print("\nLOLBIN Attack Tag Summary:\n")
    for tactic in order:
        if tactic in tactic_counts:
            print(f"{tactic}: {tactic_counts[tactic]} files")
    for tactic in sorted(tactic_counts.keys()):
        if tactic not in order:
            print(f"{tactic}: {tactic_counts[tactic]} files")
    print(f"\nTotal unique rules: {len(unique_files)}\n")
