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
    """コマンドライン引数の解析"""
    parser = argparse.ArgumentParser(
        description="ThreatStalker: Track and detect attackers using multiple rules"
    )
    # 脅威アクター名指定とATT&CKテクニックID指定は相互排他かつ必須
    group_att = parser.add_mutually_exclusive_group(required=True)
    group_att.add_argument(
        '--attackID', '-id', nargs='+',
        help="MITRE ATT&CK technique ID(s) (例: t1190, t1505)"
    )
    group_att.add_argument(
        '--threat_actor_name', '-a',
        help="脅威アクター名 (例: APT29)"
    )
    parser.add_argument(
        '--product', '-p', required=True,
        help="Product (例: windows)"
    )
    # hayabusa 実行オプション
    parser.add_argument(
        '--use-hayabusa', action='store_true',
        help="指定時、処理後にハンティングツール hayabusa を実行する"
    )
    # -d オプションと -f オプションは相互排他
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
    'chainrule' ディレクトリが存在する場合は削除し、新規作成する。
    """
    if os.path.exists(chainrule_dir):
        shutil.rmtree(chainrule_dir)
    os.makedirs(chainrule_dir)

def process_sigma_files(sigma_dir, chainrule_dir, attack_ids, product):
    """
    sigma ディレクトリ内のサブディレクトリから、指定された attackID にマッチし、
    指定された product のルールを tactic ごとに chainrule ディレクトリへコピーする。
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

                    if "tags" not in data or not isinstance(data["tags"], list):
                        continue
                    tags = data["tags"]

                    # 指定された attackIDs にマッチするテクニックタグがあるかチェック
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

                    # logsource の product が一致するかチェック
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

                    # tactic タグを抽出（テクニックタグ以外の attack. タグ）
                    tactic_tags = []
                    for tag in tags:
                        if isinstance(tag, str) and tag.startswith("attack."):
                            if not technique_pattern.match(tag):
                                tactic = tag[len("attack."):].lower()
                                tactic_tags.append(tactic)
                    if not tactic_tags:
                        tactic_tags = ["misc"]

                    unique_matched_files.add(file_path)

                    # tactic ごとにファイルを chainrule ディレクトリへコピー
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
    """各 tactic ごとのルール件数と、ユニークルールの総数を表示"""
    print("\nMITRE Tactic:\n")
    for tactic, files_set in tactic_to_files.items():
        print(f"{tactic}: {len(files_set)} files")
    print(f"\nTotal unique rules : {len(unique_matched_files)}\n\n")

def run_hayabusa_command(evtx_flag=None, evtx_file=None):
    """オプションの evtx ファイルパラメータ付きで hayabusa コマンドを実行"""
    cmd = ["hayabusa", "csv-timeline", "--no-wizard", "--quiet", "--rules", "chainrule"]
    if evtx_flag and evtx_file:
        cmd.extend([evtx_flag, evtx_file])
    try:
        subprocess.run(cmd, check=True)
    except Exception as e:
        print(f"Error running hayabusa command: {e}")

def get_group_stix_id_by_name(stix_file, group_name):
    """
    ローカルの STIX ファイルを読み込み、指定した脅威アクター名 (intrusion-set オブジェクト) の STIX ID を返す。
    """
    try:
        with open(stix_file, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        print(f"エラー: STIXファイルの読み込みに失敗しました: {e}")
        return None

    for obj in bundle.get("objects", []):
        if obj.get("type") == "intrusion-set" and obj.get("name", "").lower() == group_name.lower():
            return obj.get("id")
    return None

def get_attack_ids_by_threat_actor(stix_file, threat_actor_name):
    """
    指定した脅威アクター名から STIX ID を取得し、MitreAttackData を用いてそのグループが使用するテクニックの
    ATT&CK ID (例: t1190) 一覧を返す。
    """
    group_stix_id = get_group_stix_id_by_name(stix_file, threat_actor_name)
    if group_stix_id is None:
        print(f"脅威アクター '{threat_actor_name}' がSTIXデータ内に見つかりませんでした。")
        return None
    mitre_attack_data = MitreAttackData(stix_file)
    techniques_used = mitre_attack_data.get_techniques_used_by_group(group_stix_id)
    attack_ids = []
    print(f"{threat_actor_name} が使用するテクニック ({len(techniques_used)} 件):")
    for t in techniques_used:
        technique = t["object"]
        attack_id = mitre_attack_data.get_attack_id(technique.id)
        attack_ids.append(attack_id.lower())
        print(f"* {technique.name} ({attack_id})")
    return attack_ids

def main():
    print_logo()
    args = parse_args()

    # hayabusa を使用する場合、-d もしくは -f オプションの指定をチェック
    if args.use_hayabusa:
        if not (args.d_evtx or args.f_evtx):
            sys.exit("Error: When using hayabusa, either -d or -f must be specified.")

    product = args.product.lower()

    # 脅威アクター名が指定された場合は、STIXファイルからテクニックID群を取得
    if args.threat_actor_name:
        stix_file = "./mitre_data/enterprise-attack.json"  # ローカルに保存したSTIXファイルのパス
        attack_ids = get_attack_ids_by_threat_actor(stix_file, args.threat_actor_name)
        if not attack_ids:
            sys.exit(1)
    else:
        attack_ids = [aid.lower() for aid in args.attackID]

    current_dir = os.getcwd()
    sigma_dir = os.path.join(current_dir, "sigma")
    if not os.path.exists(sigma_dir):
        print(f"Error: '{sigma_dir}' directory does not exist.")
        sys.exit(1)

    # chainrule ディレクトリを毎回クリーンアップして再作成
    chainrule_dir = os.path.join(current_dir, "chainrule")
    clean_chainrule_directory(chainrule_dir)

    # Sigma ルールを抽出し、chainrule ディレクトリにコピー
    tactic_to_files, unique_matched_files = process_sigma_files(
        sigma_dir, chainrule_dir, attack_ids, product
    )
    print_summary(tactic_to_files, unique_matched_files)

    # hayabusa オプションが指定されていれば、実行
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
