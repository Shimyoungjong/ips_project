import pandas as pd
import glob
import os
import subprocess
import numpy as np

# ==================== 설정 ====================
CAPTURES_DIR = os.path.expanduser("~/ips_project/captures")
OUTPUT_DIR = os.path.expanduser("~/ips_project/MachineLearningCSV")

# IP 자동 감지
def get_my_ip():
    try:
        r = subprocess.run(['ipconfig', 'getifaddr', 'en0'], capture_output=True, text=True, timeout=3)
        return r.stdout.strip()
    except:
        return None

def get_ubuntu_ip():
    try:
        r = subprocess.run(
            ['ssh', '-i', os.path.expanduser('~/.ssh/id_ed25519'),
             '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3',
             'hisecure@192.168.64.10',
             "ip -4 addr show | grep 'inet ' | grep -v '192.168.64\\|127.0' | awk '{print $2}' | cut -d/ -f1"],
            capture_output=True, text=True, timeout=5
        )
        return r.stdout.strip().split('\n')[0]
    except:
        return None

MAC_IP    = get_my_ip()
UBUNTU_IP = get_ubuntu_ip()
print(f"🌐 Mac IP: {MAC_IP}")
print(f"🖥️  Ubuntu IP: {UBUNTU_IP}")

# 필터링할 IP 세트 (이 IP들 외의 트래픽은 제거)
ALLOWED_SRC = {MAC_IP, UBUNTU_IP} if MAC_IP and UBUNTU_IP else set()
ALLOWED_DST = {MAC_IP, UBUNTU_IP} if MAC_IP and UBUNTU_IP else set()

def filter_by_ip(df, label):
    if not ALLOWED_SRC:
        return df
    before = len(df)
    if 'src_ip' in df.columns and 'dst_ip' in df.columns:
        if label == 'BENIGN':
            # 정상: Mac이나 Ubuntu가 src 또는 dst인 트래픽
            df = df[df['src_ip'].isin(ALLOWED_SRC) | df['dst_ip'].isin(ALLOWED_DST)]
        else:
            # 공격: flow_key 정렬로 src/dst가 뒤집힐 수 있음 → Ubuntu가 src 또는 dst에 있는 것 모두 포함
            df = df[(df['src_ip'] == UBUNTU_IP) | (df['dst_ip'] == UBUNTU_IP)]
    after = len(df)
    print(f"  🔍 IP 필터: {before:,} → {after:,}행 (제거: {before-after:,})")
    return df
# ==============================================

# 파일명 키워드 → 라벨 매핑
LABEL_MAP = {
    'ddos':       'DDoS',
    'bruteforce': 'BruteForce',
    'portscan':   'PortScan',
    'sqli':       'SQLi',
    'xss':        'XSS',
    'normal':     'BENIGN',
    'nomal':      'BENIGN',
}

os.makedirs(OUTPUT_DIR, exist_ok=True)

# 파일 크기 기준 필터링
MAX_ROWS_PER_SESSION = 200000  # 파일당 최대 행 수
MIN_ROWS_BRUTEFORCE  = 100     # hydra 3초 세션 잡음 제외 (하한)

def get_row_count(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            return sum(1 for _ in f) - 1
    except:
        return 0

def should_exclude(filepath):
    rows = get_row_count(filepath)
    fname = os.path.basename(filepath).lower()
    if rows > MAX_ROWS_PER_SESSION:
        return True, f"크기 초과({rows:,}행)"
    if 'bruteforce' in fname and rows < MIN_ROWS_BRUTEFORCE:
        return True, f"브루트포스 잡음({rows:,}행)"
    return False, ""

all_csv = glob.glob(os.path.join(CAPTURES_DIR, "*.csv"))
excluded = []
csv_files = []
for f in all_csv:
    exc, reason = should_exclude(f)
    if exc:
        excluded.append(f"{os.path.basename(f)} ({reason})")
    else:
        csv_files.append(f)

if excluded:
    print(f"⚠️  제외된 파일:")
    for e in excluded:
        print(f"    {e}")
    print()

print(f"📂 총 {len(csv_files)}개 CSV 파일 사용\n")

# 라벨별로 파일 묶기 (bruteforce1~4 같은 경우 합치기)
label_groups = {}

for filepath in csv_files:
    fname = os.path.basename(filepath).lower()

    label = None
    for keyword, mapped_label in LABEL_MAP.items():
        if keyword in fname:
            label = mapped_label
            break

    if label is None:
        print(f"⚠️  [{os.path.basename(filepath)}] → 매핑 키워드 없음, 스킵!")
        continue

    if label not in label_groups:
        label_groups[label] = []
    label_groups[label].append(filepath)

print("📋 파일 그룹 확인:")
for label, files in label_groups.items():
    print(f"  {label}: {[os.path.basename(f) for f in files]}")
print()

# 라벨별로 합쳐서 저장
success = 0
for label, files in label_groups.items():
    try:
        dfs = []
        for filepath in files:
            df = pd.read_csv(filepath, low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)
            print(f"  읽는 중: {os.path.basename(filepath)} ({len(df):,}행)")

        # 여러 파일이면 합치기
        df_combined = pd.concat(dfs, ignore_index=True)

        # IP 필터링 (칼리→우분투 트래픽만)
        df_combined = filter_by_ip(df_combined, label)

        # 라벨 추가
        df_combined['label'] = label

        # 결측값/inf 처리
        df_combined = df_combined.replace([np.inf, -np.inf], np.nan)
        df_combined = df_combined.fillna(0)

        # 저장
        out_fname = f"{label.lower()}_labeled.csv"
        out_path = os.path.join(OUTPUT_DIR, out_fname)
        df_combined.to_csv(out_path, index=False)

        print(f"✅ [{label}] 총 {len(df_combined):,}행 → {out_fname}\n")
        success += 1

    except Exception as e:
        print(f"❌ [{label}] 오류: {e}\n")

print(f"📊 완료! {success}개 클래스 라벨링 완료")
print(f"📁 저장 위치: {OUTPUT_DIR}")
