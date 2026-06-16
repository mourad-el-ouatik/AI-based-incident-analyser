#!/usr/bin/env python3
"""
SOC ORCHESTRATOR - Version finale avec fusion des scores (Wazuh + IA)
- Lecture des alertes Wazuh via SSH
- Filtrage intelligent (niveau ≥ 5)
- Regroupement par lots (batching)
- Analyse par Mistral (streaming)
- Calcul des scores et stockage PostgreSQL
- Insertion dans OpenCTI (observables, indicateurs)
"""

import json
import time
import re
import random
import paramiko
import requests
import psycopg2
from datetime import datetime
from psycopg2.extras import Json

# ============================================================
# CONFIGURATION
# ============================================================

WAZUH_HOST = "10.125.113.20"          # IP ZeroTier du manager Wazuh
WAZUH_USER = "ubuntu"
WAZUH_PASSWORD = "ubuntu"
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "soc-analyst-v2"   # ou soc-analyst-v2

DB_CONFIG = {
    "host": "localhost",
    "database": "soc",
    "user": "soc_user",
    "password": "soc_secure_pass_2025"
}

BATCH_SIZE = 3
BATCH_TIMEOUT = 20
FILTER_LEVEL_MIN = 5
FILTER_AGENT_ID = "001"

# ============================================================
# CONFIGURATION OPENCTI
# ============================================================

OPENCTI_URL = "http://10.125.113.95:8080/graphql"
OPENCTI_TOKEN = "flgrn_octi_tkn_7bIVhaBvSMHy5jXyHaAzwhBc-Al8ufZsvoVUfuSS1OT67SXkmKUUbFCCSkir2NwL"

# ============================================================
# FILTRAGE
# ============================================================

IGNORED_LEVELS = [1, 2, 3, 4]
FALSE_POSITIVE_PATTERNS = [
    r"Successful sudo to ROOT executed",
    r"PAM: Login session (opened|closed)",
    r"session (opened|closed)",
    r"New dpkg",
    r"Dpkg",
    r"status installed",
    r"status half-configured",
    r"sudo: session",
]

def should_process_alert(alert):
    rule = alert.get("rule", {})
    level = rule.get("level", 0)
    desc = rule.get("description", "")
    if level in IGNORED_LEVELS or level < FILTER_LEVEL_MIN:
        return False
    agent_id = alert.get("agent", {}).get("id")
    if FILTER_AGENT_ID and agent_id != FILTER_AGENT_ID:
        return False
    for pat in FALSE_POSITIVE_PATTERNS:
        if re.search(pat, desc, re.IGNORECASE):
            return False
    return True

def extract_alert_info(alert):
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    return {
        "level": rule.get("level", 0),
        "description": rule.get("description", ""),
        "rule_id": rule.get("id", 0),
        "src_ip": data.get("srcip", ""),
        "src_user": data.get("srcuser", ""),
        "agent_name": alert.get("agent", {}).get("name", ""),
        "mitre": rule.get("mitre", {}).get("id", [None])[0],
        "timestamp": alert.get("timestamp", "")
    }

# ============================================================
# LECTURE WA ZUH VIA SSH
# ============================================================

class WazuhAlertReader:
    def __init__(self):
        self.ssh = None
        self.stdout = None

    def connect(self):
        print(f"🔌 Connexion SSH à {WAZUH_HOST}...")
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(hostname=WAZUH_HOST, username=WAZUH_USER,
                         password=WAZUH_PASSWORD, timeout=30)
        print("✅ Connecté")
        command = f"echo '{WAZUH_PASSWORD}' | sudo -S tail -f {ALERTS_FILE}"
        self.stdin, self.stdout, self.stderr = self.ssh.exec_command(command)
        print(f"📡 Surveillance: {ALERTS_FILE}")
        time.sleep(2)

    def read_alerts(self):
        while True:
            line = self.stdout.readline()
            if line:
                line = line.strip()
                if line.startswith('{'):
                    yield line
            else:
                time.sleep(0.1)

# ============================================================
# ANALYSE MISTRAL (STREAMING)
# ============================================================

def build_prompt(alerts_batch):
    """Construit le prompt avec le niveau Wazuh moyen."""
    alerts_text = ""
    wazuh_levels = []
    for i, alert in enumerate(alerts_batch, 1):
        lvl = alert.get('level', 0)
        wazuh_levels.append(lvl)
        alerts_text += f"{i}. Niveau Wazuh: {lvl} - {alert['description'][:100]}\n"
        if alert.get('src_ip'):
            alerts_text += f"   IP source: {alert['src_ip']}\n"
    avg_wazuh = sum(wazuh_levels) / len(wazuh_levels) if wazuh_levels else 5

    prompt = f"""Analyse ce batch de {len(alerts_batch)} alertes Wazuh:

{alerts_text}

INSTRUCTIONS :
1. Donne ton propre score d'attaque (score_ia de 1 à 10)
2. Le niveau Wazuh moyen est {avg_wazuh:.1f}/10
3. Le score_final sera la moyenne des deux

Réponds UNIQUEMENT en JSON :
{{
  "is_attack": true,
  "attack_type": "Brute Force SSH",
  "score_ia": 8,
  "score_wazuh": {avg_wazuh:.1f},
  "score_final": 7,
  "confidence": 0.9,
  "summary": "Multiple failed SSH login attempts",
  "recommended_action": "block_ip",
  "mitre_techniques": ["T1110.001"],
  "source_ip": "45.227.255.100",
  "target_user": "fakeuser",
  "target_host": "ubuntu-virtual-machine",
  "affected_service": "SSH",
  "priority": "HIGH"
}}

Adapte les valeurs en fonction des alertes reçues."""
    return prompt

def analyze_with_streaming(prompt):
    response = requests.post(OLLAMA_URL, json={
        "model": MODEL,
        "prompt": prompt,
        "stream": True
    }, stream=True, timeout=180)
    full = ""
    for line in response.iter_lines():
        if line:
            try:
                data = json.loads(line.decode('utf-8'))
                full += data.get('response', '')
                if data.get('done', False):
                    break
            except:
                pass
    full = re.sub(r'^[^{]*', '', full)
    full = re.sub(r'[^}]*$', '', full)
    try:
        return json.loads(full)
    except:
        return {
            "is_attack": False,
            "attack_type": "Unknown",
            "score_ia": 3,
            "score_wazuh": 3,
            "score_final": 3,
            "confidence": 0.5,
            "summary": "Erreur d'analyse",
            "recommended_action": "monitor",
            "mitre_techniques": [],
            "source_ip": "",
            "target_user": "",
            "target_host": "",
            "affected_service": "Unknown",
            "priority": "LOW"
        }

def save_to_postgresql(result, batch_alerts):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        # Calcul du score_wazuh réel (moyenne des niveaux du batch)
        wazuh_levels = [a.get('level', 0) for a in batch_alerts]
        avg_wazuh = sum(wazuh_levels) / len(wazuh_levels) if wazuh_levels else 5
        action = result.get("recommended_action", "monitor")
        action_map = {"monitor_only":"monitor","investigate_and_block_ip":"block_ip","block":"block_ip","isolate_host":"escalate","no_action":"monitor"}
        action = action_map.get(action, action)
        if action not in ["block_ip","escalate","monitor","false_positive"]:
            action = "monitor"
        priority = result.get("priority","LOW")
        if priority not in ["HIGH","MEDIUM","LOW"]:
            priority = "LOW"
        cur.execute("""
            INSERT INTO incidents (
                incident_id, is_attack, attack_type,
                score_wazuh, score_ia, score_final,
                confidence, summary, recommended_action,
                mitre_techniques, source_ip, target_user, target_host,
                affected_service, priority, batch_size, raw_alerts
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            f"INC-{datetime.now().strftime('%Y%m%d')}-{random.randint(100,999)}",
            result.get("is_attack", False),
            result.get("attack_type", "Unknown"),
            int(round(avg_wazuh)),
            int(result.get("score_ia", 3)),
            int(result.get("score_final", (avg_wazuh + result.get("score_ia", 3)) / 2)),
            result.get("confidence", 0.5),
            result.get("summary", ""),
            action,
            json.dumps(result.get("mitre_techniques", [])),   # ← correction JSON
            result.get("source_ip") or None,
            result.get("target_user") or None,
            result.get("target_host") or None,
            result.get("affected_service") or None,
            priority,
            len(batch_alerts),
            json.dumps(batch_alerts)
        ))
        conn.commit()
        cur.close()
        conn.close()
        print(f"   ✅ Sauvegardé (Wazuh={avg_wazuh:.1f} | IA={result.get('score_ia', '?')} | Final={result.get('score_final', '?')})")
        return True
    except Exception as e:
        print(f"   ❌ Erreur sauvegarde: {e}")
        return False

# ============================================================
# SECTION OPENCTI
# ============================================================

def send_to_opencti(analysis_result, batch_alerts):
    """
    Envoie les indicateurs clés (IP, type d'attaque) vers OpenCTI.
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENCTI_TOKEN}"
    }

    # 1. Récupérer l'IP source
    src_ip = analysis_result.get("source_ip")
    if not src_ip and batch_alerts:
        for a in batch_alerts:
            if a.get("src_ip") and a["src_ip"] not in ["127.0.0.1", "localhost"]:
                src_ip = a["src_ip"]
                break

    # 2. Créer un observable IPv4
    if src_ip:
        mutation = f"""
        mutation {{
            stixCyberObservableAdd(
                type: "IPv4-Addr",
                IPv4Addr: {{ value: "{src_ip}" }}
            ) {{
                id
                observable_value
            }}
        }}
        """
        try:
            resp = requests.post(OPENCTI_URL, json={"query": mutation}, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                obs_id = data.get("data", {}).get("stixCyberObservableAdd", {}).get("id")
                print(f"   📡 OpenCTI: Observable IPv4 créé ({src_ip}) - ID {obs_id[:8] if obs_id else '?'}...")
            else:
                print(f"   ⚠️ OpenCTI: échec création observable ({resp.status_code})")
        except Exception as e:
            print(f"   ⚠️ OpenCTI: erreur réseau {e}")

    # 3. Créer un indicateur pour l'attaque
    attack_type = analysis_result.get("attack_type", "Unknown")
    summary = analysis_result.get("summary", "")
    confidence = int(analysis_result.get("confidence", 0.5) * 100)
    mitre_techniques = analysis_result.get("mitre_techniques", [])

    if attack_type != "Unknown":
        indicator_name = f"{attack_type} - {src_ip if src_ip else 'détection'}"
        pattern = f"[ipv4-addr:value = '{src_ip}']" if src_ip else "[ipv4-addr:value = 'any']"
        mutation = f"""
        mutation {{
            indicatorAdd(
                input: {{
                    name: "{indicator_name}",
                    description: "Analyse IA: {summary}",
                    pattern: "{pattern}",
                    pattern_type: "stix",
                    confidence: {confidence},
                    valid_from: "{datetime.now().isoformat()}Z"
                }}
            ) {{
                id
            }}
        }}
        """
        try:
            resp = requests.post(OPENCTI_URL, json={"query": mutation}, headers=headers, timeout=10)
            if resp.status_code == 200:
                print(f"   📡 OpenCTI: Indicateur créé ({indicator_name[:50]}...)")
            else:
                print(f"   ⚠️ OpenCTI: échec création indicateur ({resp.status_code})")
        except Exception as e:
            print(f"   ⚠️ OpenCTI: erreur {e}")

def analyze_batch(alerts_batch):
    if len(alerts_batch) < 2:
        return None
    prompt = build_prompt(alerts_batch)
    print(f"   🤖 Envoi à Mistral...")
    result = analyze_with_streaming(prompt)
    if result and not result.get("error"):
        save_to_postgresql(result, alerts_batch)
        send_to_opencti(result, alerts_batch)
    return {
        "batch_summary": {
            "is_attack": result.get("is_attack", False),
            "global_severity": result.get("score_final", 5),
            "summary": result.get("summary", ""),
            "recommended_action": result.get("recommended_action", "monitor_only")
        },
        "alerts": [{"index": i, "classification": "true_positive" if result.get("is_attack") else "false_positive",
                    "severity": result.get("score_final", 5), "reasoning": result.get("summary", "")}
                   for i in range(len(alerts_batch))]
    }

def display_analysis(analysis, batch):
    if not analysis:
        print("   ⚠️ Aucune analyse")
        return
    s = analysis.get("batch_summary", {})
    print("\n" + "="*60)
    print("📊 ANALYSE IA")
    print("="*60)
    print(f"\n📈 RÉSUMÉ:")
    print(f"   - Attaque détectée: {'✅ OUI' if s.get('is_attack') else '❌ NON'}")
    print(f"   - Sévérité finale: {s.get('global_severity', 0)}/10")
    print(f"   - Résumé: {s.get('summary', '')}")
    print(f"   - Action recommandée: {s.get('recommended_action', 'none')}")
    print("\n" + "-"*40)
    if s.get('is_attack') and s.get('recommended_action') == "block_ip":
        for alert in batch:
            if alert.get('src_ip') and alert['src_ip'] not in ["127.0.0.1", "localhost"]:
                print(f"🎯 ACTION: Bloquer l'IP {alert['src_ip']}")
                break
        else:
            print("🎯 ACTION: Bloquer l'IP source")
    elif s.get('is_attack') and s.get('recommended_action') == "isolate_host":
        print("🚨 ACTION: Isoler l'hôte compromis")
    else:
        print("ℹ️ Surveillance continue")
    print("="*60 + "\n")

# ============================================================
# MAIN
# ============================================================

def main():
    print("="*60)
    print("🚀 SOC ORCHESTRATOR - Version Fusion des Scores + OpenCTI")
    print("="*60)
    print(f"📡 Wazuh: {WAZUH_HOST}")
    print(f"🎯 Agent: {FILTER_AGENT_ID}")
    print(f"📦 Batch: {BATCH_SIZE} alertes / {BATCH_TIMEOUT}s")
    print("="*60)

    reader = WazuhAlertReader()
    try:
        reader.connect()
    except Exception as e:
        print(f"\n❌ Connexion impossible: {e}")
        return

    buffer = []
    last_time = time.time()
    print("\n⏳ En attente d'alertes...\n")

    try:
        for line in reader.read_alerts():
            try:
                alert = json.loads(line)
            except:
                continue
            if not should_process_alert(alert):
                continue
            info = extract_alert_info(alert)
            print(f"📌 [{info['level']}] {info['description'][:60]}...")
            buffer.append(info)

            if len(buffer) >= BATCH_SIZE or (time.time() - last_time) >= BATCH_TIMEOUT:
                if len(buffer) >= 2:
                    print(f"\n🔄 Analyse batch ({len(buffer)} alertes)...")
                    analysis = analyze_batch(buffer)
                    display_analysis(analysis, buffer)
                else:
                    print(f"⏳ Batch ({len(buffer)} alerte) - attente...")
                buffer = []
                last_time = time.time()
    except KeyboardInterrupt:
        print("\n⏹️ Arrêt")
    finally:
        if reader.ssh:
            reader.ssh.close()

if __name__ == "__main__":
    main()
