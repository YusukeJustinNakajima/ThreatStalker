import os
import shutil
import re
import yaml

def clean_chainrule_directory(chainrule_dir):
    """
    If the chainrule directory exists, remove it and recreate a new one.
    """
    if os.path.exists(chainrule_dir):
        shutil.rmtree(chainrule_dir)
    os.makedirs(chainrule_dir)

def process_sigma_files(sigma_dir, chainrule_dir, attack_ids, product, tactic_filter=None):
    """
    From specified subdirectories within the sigma directory, copy YAML files
    that match the given attackIDs and product to the chainrule directory, organized by tactic.
    
    Additionally, if tactic_filter is provided, only extract files that contain a tag
    matching "attack.<tactic_filter>".
    
    Note: attack tags like 'attack.sNNNN' or 'attack.gNNNN' are ignored.
    If attack_ids is empty (i.e. filtering solely by tactics), the technique matching is bypassed.
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

                    # If attack_ids is provided, perform technique tag matching;
                    # otherwise (empty attack_ids) bypass technique matching.
                    technique_match = False
                    if attack_ids:
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
                    else:
                        technique_match = True  # bypass filtering by attack_ids

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

                    # If tactic_filter is provided,ファイルにtactic_filterが含まれなければスキップ
                    if tactic_filter is not None:
                        if tactic_filter not in tactic_tags:
                            continue
                        # tactics指定時は、コピー先フォルダはtactic_filterのみに固定
                        tactic_tags = [tactic_filter]

                    unique_matched_files.add(file_path)

                    # Copy the file into the appropriate tactic folder(s)
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

def print_summary(tactic_to_files, unique_matched_files, tactic_filter=None):
    """
    Print a summary of the number of files per tactic and total unique rules.
    When tactic_filter is provided, only show that tactic.
    Otherwise, display in the following fixed order:
    
      reconnaissance
      resource-development
      initial-access
      execution
      persistence
      privilege-escalation
      defense-evasion
      credential-access
      discovery
      lateral-movement
      collection
      command-and-control
      exfiltration
      impact
    """
    print("\nMITRE Tactic Summary:\n")
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
    if tactic_filter is not None:
        count = len(tactic_to_files.get(tactic_filter, []))
        print(f"{tactic_filter}: {count} files")
    else:
        for tactic in order:
            if tactic in tactic_to_files:
                count = len(tactic_to_files[tactic])
                print(f"{tactic}: {count} files")
        # もしorderにないフォルダがあればアルファベット順で表示
        for tactic in sorted(tactic_to_files.keys()):
            if tactic not in order:
                count = len(tactic_to_files[tactic])
                print(f"{tactic}: {count} files")
    print(f"\nTotal unique rules: {len(unique_matched_files)}\n\n")
