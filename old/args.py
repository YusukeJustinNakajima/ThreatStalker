import argparse

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="ThreatStalker",
        description="""ThreatStalker provides multi-layer filtering for threat hunting and forensic investigations.

It supports filtering on multiple levels:

1. MITRE Technique Level (point):
   - Filter based on MITRE ATT&CK technique IDs (e.g., t1190, t1505).

2. Tactics Level (line):
   - Use the --tactics option to filter sigma rules by tactic tag (e.g., initial-access, execution, etc.).

3. Detection Level (surface):
   - Filter based on threat actor TTPs using --threat_actor_name or --attackID to extract techniques specific to a threat group.

4. Advanced LOLBin Detection:
   - When the --lolbin option is specified, ThreatStalker processes LOLBAS YAML files by:
""",
        epilog="""Notes:
- ThreatStalker enables filtering at the MITRE Technique (point), Tactics (line), and Detection (surface) levels,
  allowing you to tailor your forensic and threat hunting analysis to your specific needs.
- At least one of --threat_actor_name, --attackID, --tactics, or --lolbin must be specified.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Mutually exclusive group for specifying either MITRE ATT&CK technique ID(s) or Threat Actor Name.
    group_att = parser.add_mutually_exclusive_group()
    group_att.add_argument(
        '--attackID', '-id', nargs='+',
        help="MITRE ATT&CK technique ID(s) (e.g., t1190, t1505)"
    )

    # --tactics option (can be used alone or with others)
    parser.add_argument(
        '--tactics', '-t',
        help="Filter sigma rules by tactic tag (e.g., initial-access). "
    )
    
    group_att.add_argument(
        '--threat_actor_name', '-a',
        help="Threat Actor Name (e.g., APT29) - extracts associated techniques from the MITRE STIX data"
    )
    
    # --lolbin option: Advanced LOLBin-based detection filtering
    parser.add_argument(
        '--lolbin', action='store_true',
        help=("Process LOLBAS YAML files to extract the Sigma detection filename")
    )

    parser.add_argument(
        '--product', '-p', required=True,
        help="Target product/platform (e.g., windows)"
    )
    
    parser.add_argument(
        '--use-hayabusa', action='store_true',
        help="After rule extraction, execute the hayabusa hunting tool."
    )
    
    # Mutually exclusive group for specifying the .evtx file using -d or -f
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-d", dest="d_evtx", help="Path to the .evtx file (using -d option)"
    )
    group.add_argument(
        "-f", dest="f_evtx", help="Path to the .evtx file (using -f option)"
    )
    
    args = parser.parse_args()
    
    # Ensure that at least one filtering option is specified.
    if not (args.threat_actor_name or args.attackID or args.tactics or args.lolbin):
        parser.error("One of --threat_actor_name, --attackID, --tactics, or --lolbin must be specified.")
    
    return args
