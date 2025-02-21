import sys
import json
from mitreattack.stix20 import MitreAttackData

def get_group_stix_id_by_name(stix_file, group_name):
    """
    ローカルの STIX データファイルを直接読み込み、指定した脅威アクター名 (intrusion-set オブジェクト) の STIX ID を返す。
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

def main():
    # コマンドライン引数から脅威アクター名を受け取る
    if len(sys.argv) < 2:
        print("Usage: python3 test3.py <Threat Actor Name>")
        sys.exit(1)
    
    threat_actor_name = sys.argv[1]
    stix_file = "enterprise-attack.json"  # ローカルに保存したSTIXファイルのパス

    # 脅威アクター名から STIX ID を取得
    group_stix_id = get_group_stix_id_by_name(stix_file, threat_actor_name)
    if group_stix_id is None:
        print(f"脅威アクター '{threat_actor_name}' がSTIXデータ内に見つかりませんでした。")
        sys.exit(1)

    # MitreAttackData オブジェクトを生成
    mitre_attack_data = MitreAttackData(stix_file)

    # 取得した STIX ID から、そのグループが使用するテクニックを取得
    techniques_used = mitre_attack_data.get_techniques_used_by_group(group_stix_id)

    print(f"{threat_actor_name} が使用するテクニック ({len(techniques_used)} 件):")
    for t in techniques_used:
        technique = t["object"]
        print(f"* {technique.name} ({mitre_attack_data.get_attack_id(technique.id)})")

if __name__ == "__main__":
    main()
