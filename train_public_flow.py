#!/usr/bin/env python3
"""
흐름(Flow) 탐지 모델 — 공개 데이터셋 학습 + 직접 캡처 데이터로 교차 검증
- 학습 데이터: CIC-IDS-2017 improved (Liu, Engelen et al., IEEE CNS 2022)
  https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html
  → public_dataset/cicids2017/{monday..friday}.csv
- 교차 검증: 직접 공격을 보내 캡처한 MachineLearningCSV/*_labeled.csv (학습에 사용하지 않음)
- 실시간 탐지(scapy_flow.py)와 피처 정의를 맞추기 위해 CIC 값을 scapy_flow 방식으로 변환
  · 패킷 길이: CIC=페이로드만 / scapy_flow=IP 패킷 전체 → 패킷당 IP(20) + TCP/UDP 헤더 길이를 더함
  · 헤더 길이: CIC=전송계층 헤더만 / scapy_flow=IP+전송계층 → 패킷당 20을 더함
  · scapy_flow가 실제로 계산하지 않는 피처(active/idle, bulk)는 제외
- 결과는 _public 접미사로 저장 (기존 rf_model.pkl은 그대로 둠)
"""

import glob
import os
import time

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

IPS_HOME   = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(IPS_HOME, "public_dataset", "cicids2017")
OWN_DIR    = os.path.join(IPS_HOME, "MachineLearningCSV")
MODEL_DIR  = os.path.join(IPS_HOME, "models")

CLASSES   = ["BENIGN", "BruteForce", "DDoS", "PortScan"]
CAP       = {"BENIGN": 300000, "DDoS": 150000, "PortScan": 150000, "BruteForce": None}
TEST_SIZE = 0.25
OWN_CAP   = 30000  # 교차 검증 시 클래스당 최대 샘플 수

LABEL_MAP = {
    "BENIGN": "BENIGN",
    "Portscan": "PortScan", "Infiltration - Portscan": "PortScan",
    "DDoS": "DDoS", "DoS Hulk": "DDoS", "DoS GoldenEye": "DDoS",
    "DoS Slowloris": "DDoS", "DoS Slowhttptest": "DDoS",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce", "Web Attack - Brute Force": "BruteForce",
}

# CIC 컬럼 → scapy_flow 피처 이름
CIC_COLS = {
    "Flow Duration": "flow_duration",
    "Total Fwd Packet": "tot_fwd_pkts", "Total Bwd packets": "tot_bwd_pkts",
    "Total Length of Fwd Packet": "totlen_fwd_pkts", "Total Length of Bwd Packet": "totlen_bwd_pkts",
    "Fwd Packet Length Max": "fwd_pkt_len_max", "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean", "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max", "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean", "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Packet Length Std": "pkt_len_std", "Packet Length Variance": "pkt_len_var",
    "Flow IAT Mean": "flow_iat_mean", "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max", "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_tot", "Fwd IAT Mean": "fwd_iat_mean", "Fwd IAT Std": "fwd_iat_std", "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Mean": "bwd_iat_mean", "Bwd IAT Std": "bwd_iat_std", "Bwd IAT Min": "bwd_iat_min",
    "Fwd Header Length": "fwd_header_len", "Bwd Header Length": "bwd_header_len",
    "FIN Flag Count": "fin_flag_cnt", "SYN Flag Count": "syn_flag_cnt", "RST Flag Count": "rst_flag_cnt",
    "PSH Flag Count": "psh_flag_cnt", "ACK Flag Count": "ack_flag_cnt",
    "FWD Init Win Bytes": "init_fwd_win_byts", "Bwd Init Win Bytes": "init_bwd_win_byts",
}

# train_mydata.py의 TOP_FEATURES에서 scapy_flow가 실제로 계산하지 않는 피처를 뺀 목록
FEATURES = [
    'init_fwd_win_byts', 'init_bwd_win_byts', 'bwd_seg_size_avg',
    'bwd_pkt_len_mean', 'pkt_len_mean', 'bwd_pkt_len_std', 'pkt_size_avg',
    'fwd_header_len', 'bwd_header_len', 'totlen_fwd_pkts', 'fwd_pkt_len_max',
    'pkt_len_var', 'subflow_fwd_pkts', 'subflow_fwd_byts', 'tot_fwd_pkts',
    'pkt_len_min', 'fwd_seg_size_avg', 'pkt_len_std', 'bwd_pkt_len_max',
    'fwd_pkt_len_mean', 'totlen_bwd_pkts', 'fwd_pkt_len_std',
    'subflow_bwd_byts', 'pkt_len_max',
    'flow_duration', 'flow_byts_s', 'flow_pkts_s', 'fwd_pkts_s', 'bwd_pkts_s',
    'fwd_act_data_pkts', 'down_up_ratio',
    'flow_iat_mean', 'flow_iat_std', 'flow_iat_min', 'flow_iat_max',
    'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_min', 'fwd_iat_tot',
    'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_min',
    'syn_flag_cnt', 'fin_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt',
    'win_ratio', 'payload_ratio', 'fwd_bwd_pkt_ratio', 'pkt_len_range',
    'iat_cv', 'fwd_iat_cv', 'pkt_per_flow',
    'syn_ratio', 'fin_ratio', 'rst_ratio', 'bytes_per_pkt', 'header_ratio',
]


def add_derived(df):
    """realtime_detect.py / train_mydata.py와 동일한 파생 피처."""
    df['win_ratio']         = df['init_fwd_win_byts'] / (df['init_bwd_win_byts'] + 1)
    df['payload_ratio']     = df['totlen_fwd_pkts']   / (df['totlen_bwd_pkts']   + 1)
    df['fwd_bwd_pkt_ratio'] = df['tot_fwd_pkts']      / (df['tot_bwd_pkts']      + 1)
    df['pkt_len_range']     = df['pkt_len_max']        - df['pkt_len_min']
    df['iat_cv']            = df['flow_iat_std']  / (df['flow_iat_mean']  + 1)
    df['fwd_iat_cv']        = df['fwd_iat_std']   / (df['fwd_iat_mean']   + 1)
    df['pkt_per_flow']      = (df['tot_fwd_pkts'] + df['tot_bwd_pkts']) / (df['flow_duration'] + 1)
    total_pkts              = df['tot_fwd_pkts'] + df['tot_bwd_pkts'] + 1
    df['syn_ratio']         = df['syn_flag_cnt'] / total_pkts
    df['fin_ratio']         = df['fin_flag_cnt'] / total_pkts
    df['rst_ratio']         = df['rst_flag_cnt'] / total_pkts
    df['bytes_per_pkt']     = df['flow_byts_s']  / (df['flow_pkts_s'] + 1)
    df['header_ratio']      = (df['fwd_header_len'] + df['bwd_header_len']) / (df['totlen_fwd_pkts'] + df['totlen_bwd_pkts'] + 1)
    return df.replace([np.inf, -np.inf], np.nan).fillna(0).clip(-1e15, 1e15)


def cic_to_scapy(raw):
    """CIC-IDS-2017 행을 scapy_flow.py가 실시간으로 계산하는 값의 정의로 변환."""
    d = raw.rename(columns=CIC_COLS)
    nf = d['tot_fwd_pkts'].astype(float)
    nb = d['tot_bwd_pkts'].astype(float)
    # 패킷당 추가 길이 = IP 헤더(20) + 전송계층 헤더 평균
    add_f = np.where(nf > 0, 20 + d['fwd_header_len'] / nf.clip(lower=1), 0)
    add_b = np.where(nb > 0, 20 + d['bwd_header_len'] / nb.clip(lower=1), 0)
    for c in ('fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean'):
        d[c] = d[c] + add_f
    for c in ('bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean'):
        d[c] = d[c] + add_b
    d['totlen_fwd_pkts'] = d['totlen_fwd_pkts'] + nf * add_f
    d['totlen_bwd_pkts'] = d['totlen_bwd_pkts'] + nb * add_b
    d['fwd_header_len']  = d['fwd_header_len'] + 20 * nf
    d['bwd_header_len']  = d['bwd_header_len'] + 20 * nb

    total = nf + nb
    d['pkt_len_mean'] = (d['totlen_fwd_pkts'] + d['totlen_bwd_pkts']) / total.clip(lower=1)
    d['pkt_len_max']  = np.where(nb > 0, np.maximum(d['fwd_pkt_len_max'], d['bwd_pkt_len_max']), d['fwd_pkt_len_max'])
    d['pkt_len_min']  = np.where(nb > 0, np.minimum(d['fwd_pkt_len_min'], d['bwd_pkt_len_min']), d['fwd_pkt_len_min'])

    dur_s = (d['flow_duration'] / 1e6).clip(lower=1e-9)
    d['flow_byts_s'] = (d['totlen_fwd_pkts'] + d['totlen_bwd_pkts']) / dur_s
    d['flow_pkts_s'] = total / dur_s
    d['fwd_pkts_s']  = nf / dur_s
    d['bwd_pkts_s']  = nb / dur_s

    # scapy_flow.py와 동일한 정의
    d['pkt_size_avg']      = d['pkt_len_mean']
    d['fwd_seg_size_avg']  = d['fwd_pkt_len_mean']
    d['bwd_seg_size_avg']  = d['bwd_pkt_len_mean']
    d['fwd_act_data_pkts'] = nf                       # scapy는 IP 길이 > 0 이라 항상 전체 fwd 패킷 수
    d['down_up_ratio']     = nb / nf.clip(lower=1)
    d['subflow_fwd_pkts']  = nf
    d['subflow_fwd_byts']  = d['totlen_fwd_pkts']
    d['subflow_bwd_byts']  = d['totlen_bwd_pkts']
    d['init_fwd_win_byts'] = d['init_fwd_win_byts'].clip(lower=0)
    d['init_bwd_win_byts'] = d['init_bwd_win_byts'].clip(lower=0)
    return d


def load_public():
    usecols = list(CIC_COLS) + ["Label", "Attempted Category"]
    parts = []
    for f in sorted(glob.glob(os.path.join(PUBLIC_DIR, "*.csv"))):
        df = pd.read_csv(f, usecols=usecols, low_memory=False)
        # 저자 권고: Attempted 흐름은 별도 라벨로 쓰지 말고 BENIGN으로 재라벨링
        df.loc[df["Attempted Category"] != -1, "Label"] = "BENIGN"
        df["label"] = df["Label"].map(LABEL_MAP)
        df = df.dropna(subset=["label"])
        # scapy_flow는 2패킷 미만 흐름을 버림 / CIC 헤더 길이 음수 버그 행 제외
        df = df[(df["Total Fwd Packet"] + df["Total Bwd packets"] >= 2)
                & (df["Fwd Header Length"] >= 0) & (df["Bwd Header Length"] >= 0)]
        parts.append(df.drop(columns=["Label", "Attempted Category"]))
        print(f"  {os.path.basename(f)}: {len(df):,}행")
    df = pd.concat(parts, ignore_index=True)
    sampled = []
    for label, g in df.groupby("label"):
        cap = CAP[label]
        sampled.append(g if cap is None or len(g) <= cap else g.sample(cap, random_state=42))
    df = pd.concat(sampled, ignore_index=True)
    y = df.pop("label")
    X = add_derived(cic_to_scapy(df.apply(pd.to_numeric, errors="coerce").fillna(0)))
    return X[FEATURES], y


def load_own():
    parts = []
    for f in glob.glob(os.path.join(OWN_DIR, "*_labeled.csv")):
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        df["label"] = df["label"].astype(str).str.strip()
        df = df[df["label"].isin(CLASSES)]
        if len(df) > OWN_CAP:
            df = df.sample(OWN_CAP, random_state=42)
        parts.append(df)
    df = pd.concat(parts, ignore_index=True)
    y = df.pop("label")
    X = df.drop(columns=[c for c in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp"] if c in df.columns])
    X = add_derived(X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0))
    return X[FEATURES], y


def save_cm(y_true, y_pred, title, path):
    cm = confusion_matrix(y_true, y_pred, labels=CLASSES)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', xticklabels=CLASSES, yticklabels=CLASSES, cmap='Blues')
    plt.title(title)
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def main():
    print("📥 공개 데이터(CIC-IDS-2017 improved) 로드...")
    X, y = load_public()
    print(f"✅ {len(X):,}행 / 피처 {len(FEATURES)}개\n{y.value_counts()}\n")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=TEST_SIZE, random_state=42, stratify=y)

    print("🌲 학습 중...")
    start = time.time()
    model = RandomForestClassifier(
        n_estimators=200, max_depth=25, min_samples_leaf=2,
        class_weight="balanced_subsample", random_state=42, n_jobs=-1,
    )
    model.fit(X_train, y_train)
    print(f"⏱️ {time.time() - start:.1f}초\n")

    y_pred = model.predict(X_test)
    print(f"📊 [1] 공개 데이터 held-out ({len(X_test):,}건) 정확도: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, digits=3))
    save_cm(y_test, y_pred, "Flow model (public) - CIC-IDS-2017 held-out", os.path.join(MODEL_DIR, "confusion_matrix_public_heldout.png"))

    print("📥 직접 캡처 데이터(MachineLearningCSV) 로드...")
    X_own, y_own = load_own()
    y_own_pred = model.predict(X_own)
    print(f"📊 [2] 교차 검증: 공개 데이터로 학습 → 직접 캡처 데이터 ({len(X_own):,}건) 정확도: {accuracy_score(y_own, y_own_pred):.4f}")
    print(classification_report(y_own, y_own_pred, digits=3, zero_division=0))
    print(pd.crosstab(y_own, y_own_pred, rownames=["실제"], colnames=["예측"]))
    save_cm(y_own, y_own_pred, "Flow model (public) - own captures", os.path.join(MODEL_DIR, "confusion_matrix_public_own.png"))

    joblib.dump(model, os.path.join(MODEL_DIR, "rf_model_public.pkl"), compress=3)
    joblib.dump(FEATURES, os.path.join(MODEL_DIR, "feature_names_public.pkl"))
    joblib.dump(list(model.classes_), os.path.join(MODEL_DIR, "classes_public.pkl"))
    print(f"\n✅ 저장 완료 (기존 rf_model.pkl은 그대로 둠): rf_model_public.pkl / feature_names_public.pkl / classes_public.pkl")


if __name__ == "__main__":
    main()
