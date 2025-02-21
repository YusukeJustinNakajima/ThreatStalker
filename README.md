# ThreatStalker
ThreatStalker enables filtering at the MITRE Technique (point), Tactics (line), and Detection (surface) levels,
allowing you to tailor your forensic and threat hunting analysis to your specific need.

![image-1](https://github.com/user-attachments/assets/df8f100c-8dbc-4992-9813-c1205dab4f89)


## Purpose
- Vendor-independent Sigma rules play a crucial role in threat hunting and SOC operations, as they are widely used by many organizations. However, as mentioned in 
[MITRE's Summiting the Pyramid](https://ctid.mitre.org/projects/summiting-the-pyramid/), **many detection rules can be easily evaded by attackers.**
- Moreover, increasing detection coverage often leads to a surge in false positives, overwhelming analysts with excessive alerts. Addressing this trade-off is therefore of utmost importance.
- This project leverages MITRE’s knowledge to enable flexible selection and application of Sigma rules across multiple levels: technique-level (point), tactics-level (line), adversary-level (surface), and LoLBin-level, reflecting the recent trend of Living off the Land attacks.
- By doing so, **even attacks that may evade a single detection rule can be identified when analyzed as part of a broader attack chain. Additionally, filtering based on specific needs helps to suppress false positives,** ensuring a more effective detection process.

## Preparation
### Step1
Clone the repository:
```bash
git clone https://github.com/YusukeJustinNakajima/ThreatStalker.git
cd ThreatStalker
```
### Step2
Installing Dependencies:
```bash
pip install -r requirements.txt
```
### Step3
Download Hayabusa Binary from https://github.com/Yamato-Security/hayabusa


### How to use
Filtering by Attack ID:
```bash
python3 ThreatStalker.py --attackID t1190 --product windows
```

Filtering by Tactics:
```bash
python3 ThreatStalker.py --tactics execution --product windows
```

Filtering by Actors:
```bash
python3 ThreatStalker.py --threat_actor_name APT37 --product windows
```

Filtering by LoLbin:
```bash
python3 ThreatStalker.py --lolbin --product windows
```

Filtering by Actors and Apply these rules using Hayabusa
```bash
python3 ThreatStalker.py --threat_actor_name APT37 --product windows --use-hayabusa -d hayabusa-sample-evtx/EVTX-ATTACK-SAMPLES/
```

**All filtered rules are placed within "chainrules" directory, organized by tactics.**

## Future Works
- Robustness testing functionality for Sigma rules
- Integration of the [Technique Inference Engine (TIE)](https://center-for-threat-informed-defense.github.io/technique-inference-engine/#/)
- Integration with other hunting tools (e.g., [Chainsaw](https://github.com/WithSecureLabs/chainsaw[), [Zircolite](https://github.com/wagga40/Zircolite))
- Integration of functionality for converting Sigma rules to SIEM rules
