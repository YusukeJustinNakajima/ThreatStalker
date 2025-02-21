import json
from mitreattack.stix20 import MitreAttackData

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
