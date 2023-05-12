import pandas as pd

# semantic_pairings_filepath = "MS_CS_semantic_pairings_v2.xlsx"
semantic_pairings_filepath = "MS_CS_semantic_pairings_v4_JSON.xlsx"
# key_filepath = "Manual_Updated_Key_v1.xlsx"
key_filepath = "Recursive_Search_Key_v3.xlsx"

# Read both Excel files into pandas DataFrames
semantic_pairings_df = pd.read_excel(semantic_pairings_filepath, sheet_name= 'MS_to_CS_Pairs')
# semantic_pairings_df = pd.read_excel(semantic_pairings_filepath, sheet_name= 'CS_to_MS_Pairs')
"""
4.24.23 If I can cross validate between MS_to_CS_Pairs and CS_to_MS_Pairs, I can get more accuracy.
However, first draft I will use just single path validation from MS_to_CS_Pairs
"""
key_df = pd.read_excel(key_filepath)

# Initialize the match counter
match_count = 0

# Iterate through both DataFrames and compare JSON values
for key_index, key_row in key_df.iterrows():
    ms_key_json = key_row['MS JSON']
    cs_key_json = key_row['CS JSON']

    for pair_index, pair_row in semantic_pairings_df.iterrows():
        ms_pair_json = pair_row['ms_json']
        cs_pair_json = pair_row['cs_json']

        if ms_key_json == ms_pair_json and cs_key_json == cs_pair_json:
            match_count += 1

            break

"""
Manually looked over the MS_Below_Threhold and CS_Below_Threshold sheets and found 6 more standalone matches.
{"AlertName": "Abuse of Elevation Control Mechanism Detected", "AlertDescription": "Abuse of an elevation control mechanism was detected on the following device: {Device_Name}. The user {User_Name} attempted to elevate their privileges without authorization by running {Executable_Name} with elevated privileges.", "Severity": "High", "Category": "Privilege Escalation", "Tactic": "Privilege Escalation", "Technique": "Abuse Elevation Control Mechanism", "Malicious_Executable": "{Executable_Name}"}
{"AlertName": "Drive-by Compromise Detected", "AlertDescription": "This alert fires when a drive-by compromise attempt is detected on an endpoint.", "Severity": "High", "AlertCategory": "Malware", "EntityType": "Host", "EntityName": "COMPANY-PC01", "RecommendedActions": ["Isolate the affected host immediately", "Scan the host with an antivirus or EDR tool", "Investigate the network traffic and identify the source of the attack"], "References": ["https://attack.mitre.org/techniques/T1189/", "https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/drive-by-compromise"]}
{"AlertName": "Modify Authentication Process", "AlertDescription": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials.", "Tactic": "Defense Evasion", "Technique": "Modify Authentication Process", "Severity": "Critical", "Source": "Endpoint", "Host": "server01", "RegistryKey": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "RegistryValue": "Userinit", "Action": "Blocked", "Reason": "Unauthorized modification of registry key"}

{"event": {"event_type": "threat detection", "severity": "high", "event_description": "Dynamic Resolution detected", "event_category": "dymanic resolution", "source": {"type": "endpoint"}, "attack_name": "Dynamic Resolution", "tactic": "Defense Evasion"}}
{"event": {"event_type": "alert", "event_severity": "medium", "rule_name": "Encrypted Channel", "event_description": "Encrypted Channel detected", "event_category": "encrypted channel", "process_name": "powershell.exe"}}
{"event": {"event_type": "threat detection", "type": "THREAT", "event_category": "Suspicious Shared Module Loaded", "event_description": "Adversaries may execute malicious payloads via loading shared modules.", "domain": "mydomain.local", "ip_addresses": ["192.168.1.100", "fe80::1234:5678:90ab:cdef"], "mac_addresses": ["00:11:22:33:44:55"], "agent_version": "6.30.0.0", "group_name": "Workstations"}}

"""
match_count += 6

print(f"Total matches: {match_count}")
print(f"Total key rows: {len(key_df)}")
# calculate % of matches
print(f"Percentage of matches: {match_count / len(key_df) * 100}%")
"""
v2 Result with threshold implementation improved match accuracy by 3%!
Total matches: 84
Total key rows: 98
Percentage of matches: 85.71428571428571%

v4 Result with better cleaned data + JSON scoring implementation improved match accuracy by 1%!
Total matches: 85
Total key rows: 98
Percentage of matches: 86.73469387755102%
"""
