#!/usr/bin/env python3
# Ubuntu에서 실행: python3 patch_detect.py
# detect_attack() 함수에서 HTTP ML이 DDoS보다 먼저 실행되도록 수정

path = '/root/ips_project/vulnerable_server/app.py'

with open(path, 'r', encoding='utf-8') as f:
    src = f.read()

# detect_attack 전체 함수를 새 버전으로 교체
import re

NEW_FUNC = '''@app.before_request
def detect_attack():
    attacker_ip = request.remote_addr
    now = time.time()

    # ========== HTTP ML 탐지 먼저 (SQLi/XSS) — DDoS보다 우선 ==========
    all_values = []
    for v in request.args.values():
        all_values.append(v)
    for v in request.form.values():
        all_values.append(v)

    if all_values:
        payload = ' '.join(all_values)
        feat = extract_features(payload)
        X = pd.DataFrame([[feat[f] for f in http_features]], columns=http_features)
        pred = model_http.predict(X)[0]
        conf = float(model_http.predict_proba(X).max())

        if pred != 'BENIGN' and conf >= 0.75:
            print(f"[{pred} 탐지] IP: {attacker_ip} | 신뢰도: {conf:.1%}")
            threading.Thread(target=send_alert, args=(pred, attacker_ip, conf)).start()
            return  # SQLi/XSS 잡혔으면 DDoS 체크 스킵

    # ========== DDoS 탐지 (HTTP ML에서 못 잡은 경우만) ==========
    request_times[attacker_ip] = [t for t in request_times[attacker_ip] if now - t < 1.0]
    request_times[attacker_ip].append(now)
    if len(request_times[attacker_ip]) > DDOS_THRESHOLD:
        print(f"[DDoS 탐지] IP: {attacker_ip} | 초당 {len(request_times[attacker_ip])}회")
        threading.Thread(target=send_alert, args=("DDoS", attacker_ip, 0.97)).start()
'''

# @app.before_request\ndef detect_attack(): 부터 다음 @app. 또는 # ==== 까지를 교체
pattern = r'(@app\.before_request\s*\ndef detect_attack\(\):.*?)(?=\n# ={10,}|\n@app\.|\nrequest_times\s*=|\nDDOS_THRESHOLD)'
match = re.search(pattern, src, re.DOTALL)

if match:
    src = src[:match.start()] + NEW_FUNC + src[match.end():]
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    print("✅ 패치 완료!")
    print("   → HTTP ML(SQLi/XSS)이 DDoS 체크보다 먼저 실행됩니다")
    print("   → sqlmap이 SQLi로 올바르게 탐지됩니다")
else:
    print("❌ 패치 실패 — detect_attack 함수를 찾지 못했습니다")
    print(f"   파일에서 'detect_attack' 위치: {src.find('def detect_attack')}")
