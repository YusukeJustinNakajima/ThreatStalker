# ThreatStalker
ThreatStalker enables filtering at the MITRE Technique (point), Tactics (line), and Detection (surface) levels,
allowing you to tailor your forensic and threat hunting analysis to your specific need.

## Purpose
- Vendor-independent Sigma rules play a crucial role in threat hunting and SOC operations, as they are widely used by many organizations. However, as mentioned in 
[MITRE's Summiting the Pyramid](https://ctid.mitre.org/projects/summiting-the-pyramid/), **many detection rules can be easily evaded by attackers.**
- Moreover, increasing detection coverage often leads to a surge in false positives, overwhelming analysts with excessive alerts. Addressing this trade-off is therefore of utmost importance.
- This project leverages MITRE’s knowledge to enable flexible selection and application of Sigma rules across multiple levels: technique-level (point), tactics-level (line), adversary-level (surface), and LoLBin-level, reflecting the recent trend of Living off the Land attacks.
- By doing so, even attacks that may evade a single detection rule can be identified when analyzed as part of a broader attack chain. Additionally, filtering based on specific needs helps to suppress false positives, ensuring a more effective detection process.
## Features
## How to use
## Future Works
