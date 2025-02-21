import json
from stix2 import MemoryStore, Filter

# ローカルのSTIXデータファイルを読み込む
stix_file = "enterprise-attack.json"  # ローカルのSTIXデータファイル

try:
    with open(stix_file, "r", encoding="utf-8") as file:
        stix_data = json.load(file)
except Exception as e:
    print(f'エラー: STIXデータの読み込みに失敗しました: {e}')
    exit(1)

# STIXデータが 'objects' キーを持っているか確認
if 'objects' not in stix_data:
    print('エラー: STIXデータに "objects" キーが存在しません。')
    exit(1)

# STIXデータをMemoryStoreにロード
memory_store = MemoryStore(stix_data=stix_data['objects'])

# データが正しくロードされたか確認
if not list(memory_store.query()):
    print('エラー: MemoryStore にデータが正しくロードされていません。')
    exit(1)

# オブジェクト名からSTIX IDを取得する関数
def get_stix_id_by_name(object_name, object_type):
    # Filterオブジェクトを使ってフィルター条件を指定
    filters = [
        Filter("type", "=", object_type),
        Filter("name", "=", object_name)
    ]
    results = list(memory_store.query(filters))
    if results:
        return results[0]['id']
    else:
        return None

# 使用例
object_name = 'Naikon'
object_type = 'intrusion-set'  # 脅威アクター（攻撃グループ）の場合
stix_id = get_stix_id_by_name(object_name, object_type)

if stix_id:
    print(f'オブジェクト名 "{object_name}" のSTIX IDは {stix_id} です。')
else:
    print(f'オブジェクト名 "{object_name}" に対応するSTIX IDが見つかりませんでした。')
