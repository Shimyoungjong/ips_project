#!/usr/bin/env python3
"""
IPS 모델 성능 테스트 스크립트
사용법:
  합성 데이터 즉시 테스트:
    python3 test_model.py --synthetic
  CICIDS2017 CSV 테스트:
    python3 test_model.py --csv Wednesday-workingHours.pcap_ISCX.csv
"""

import argparse, sys
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

MODEL_DIR = Path(__file__).parent / "models"

def load_model():
    # train_mydata.py가 joblib.dump()로 저장한 파일이라 joblib.load()로 읽어야 함.
    # plain pickle.load()를 쓰면 "_pickle.UnpicklingError: STACK_GLOBAL requires str" 발생.
    model = joblib.load(MODEL_DIR / "rf_model.pkl")
    feature_names = list(joblib.load(MODEL_DIR / "feature_names.pkl"))
    # train_mydata.py는 스케일러를 만들지 않음 (RandomForest는 피처 스케일링이 필요 없음).
    # models/scaler.pkl은 존재하지 않으므로 더 이상 로드하지 않음.
    return model, feature_names

# CICIDS2017 컬럼 → 모델 피처명 매핑
CIC_MAP = {
    "Flow Duration":"flow_duration","Total Fwd Packets":"tot_fwd_pkts",
    "Total Length of Fwd Packets":"totlen_fwd_pkts","Total Length of Bwd Packets":"totlen_bwd_pkts",
    "Fwd Packet Length Max":"fwd_pkt_len_max","Fwd Packet Length Mean":"fwd_pkt_len_mean",
    "Fwd Packet Length Std":"fwd_pkt_len_std","Bwd Packet Length Max":"bwd_pkt_len_max",
    "Bwd Packet Length Mean":"bwd_pkt_len_mean","Bwd Packet Length Std":"bwd_pkt_len_std",
    "Flow Bytes/s":"flow_byts_s","Flow Packets/s":"flow_pkts_s",
    "Flow IAT Mean":"flow_iat_mean","Flow IAT Std":"flow_iat_std",
    "Flow IAT Min":"flow_iat_min","Flow IAT Max":"flow_iat_max",
    "Fwd IAT Total":"fwd_iat_tot","Fwd IAT Mean":"fwd_iat_mean",
    "Fwd IAT Std":"fwd_iat_std","Fwd IAT Min":"fwd_iat_min",
    "Bwd IAT Mean":"bwd_iat_mean","Bwd IAT Std":"bwd_iat_std","Bwd IAT Min":"bwd_iat_min",
    "Fwd Header Length":"fwd_header_len","Bwd Header Length":"bwd_header_len",
    "Fwd Packets/s":"fwd_pkts_s","Bwd Packets/s":"bwd_pkts_s",
    "Packet Length Min":"pkt_len_min","Packet Length Max":"pkt_len_max",
    "Packet Length Mean":"pkt_len_mean","Packet Length Std":"pkt_len_std",
    "Packet Length Variance":"pkt_len_var","SYN Flag Count":"syn_flag_cnt",
    "FIN Flag Count":"fin_flag_cnt","RST Flag Count":"rst_flag_cnt",
    "PSH Flag Count":"psh_flag_cnt","ACK Flag Count":"ack_flag_cnt",
    "Down/Up Ratio":"down_up_ratio","Average Packet Size":"pkt_size_avg",
    "Avg Fwd Segment Size":"fwd_seg_size_avg","Avg Bwd Segment Size":"bwd_seg_size_avg",
    "Fwd Act Data Packets":"fwd_act_data_pkts","Fwd Bytes/Bulk Avg":"fwd_byts_b_avg",
    "Init_Win_bytes_forward":"init_fwd_win_byts","Init_Win_bytes_backward":"init_bwd_win_byts",
    "Subflow Fwd Packets":"subflow_fwd_pkts","Subflow Fwd Bytes":"subflow_fwd_byts",
    "Subflow Bwd Bytes":"subflow_bwd_byts","Active Mean":"active_mean",
    "Active Std":"active_std","Idle Mean":"idle_mean","Idle Std":"idle_std",
}

LABEL_MAP = {
    "BENIGN":"BENIGN","DoS Hulk":"DDoS","DoS GoldenEye":"DDoS",
    "DoS slowloris":"DDoS","DoS Slowhttptest":"DDoS","DDoS":"DDoS",
    "PortScan":"PortScan","FTP-Patator":"BruteForce","SSH-Patator":"BruteForce",
    "Bot":"BruteForce","Infiltration":"BruteForce","Heartbleed":"DDoS",
    "Web Attack \x96 Brute Force":"BruteForce","Web Attack \x96 Sql Injection":"SQLi",
    "Web Attack \x96 XSS":"XSS","Web Attack – Brute Force":"BruteForce",
    "Web Attack – Sql Injection":"SQLi","Web Attack – XSS":"XSS",
}

def add_derived(df):
    eps = 1e-9
    df["win_ratio"] = df.get("init_fwd_win_byts",0) / (df.get("init_bwd_win_byts",0)+eps)
    tb = df.get("totlen_fwd_pkts",0) + df.get("totlen_bwd_pkts",0)
    df["payload_ratio"] = df.get("totlen_fwd_pkts",0) / (tb+eps)
    tp = df.get("tot_fwd_pkts",0) + df.get("subflow_fwd_pkts",df.get("tot_fwd_pkts",0))
    df["fwd_bwd_pkt_ratio"] = df.get("tot_fwd_pkts",0) / (tp+eps)
    tf = df.get("syn_flag_cnt",0)+df.get("ack_flag_cnt",0)+df.get("fin_flag_cnt",0)+df.get("rst_flag_cnt",0)+eps
    df["syn_ratio"]  = df.get("syn_flag_cnt",0)/tf
    df["fin_ratio"]  = df.get("fin_flag_cnt",0)/tf
    df["rst_ratio"]  = df.get("rst_flag_cnt",0)/tf
    df["pkt_len_range"] = df.get("pkt_len_max",0)-df.get("pkt_len_min",0)
    df["iat_cv"]     = df.get("flow_iat_std",0)/(df.get("flow_iat_mean",0)+eps)
    df["fwd_iat_cv"] = df.get("fwd_iat_std",0)/(df.get("fwd_iat_mean",0)+eps)
    df["pkt_per_flow"]= tp/(df.get("flow_duration",1)+eps)
    df["active_idle_ratio"]=df.get("active_mean",0)/(df.get("idle_mean",0)+eps)
    df["bytes_per_pkt"]=tb/(tp+eps)
    df["header_ratio"]=df.get("fwd_header_len",0)/(tb+eps)
    return df

def run_report(y_true, y_pred, proba):
    from sklearn.metrics import classification_report, accuracy_score
    acc = accuracy_score(y_true, y_pred)
    print(f"\n{'='*55}")
    print(f"  전체 정확도 : {acc*100:.2f}%")
    print(f"  평균 신뢰도 : {proba.mean()*100:.2f}%")
    print(f"{'='*55}")
    print(classification_report(y_true, y_pred, zero_division=0))
    print("클래스별 상세:")
    for cls in sorted(set(y_true)):
        m = y_true==cls
        print(f"  {cls:<12} 정확도:{(y_pred[m]==cls).mean()*100:5.1f}%  신뢰도:{proba[m].mean()*100:5.1f}%  n={m.sum()}")

def test_csv(path, model, fn, n=5000):
    print(f"\n📂 {path}")
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    lc = next((c for c in df.columns if "label" in c.lower()), None)
    if not lc: sys.exit("❌ Label 컬럼 없음")
    df["_label"] = df[lc].str.strip().map(LABEL_MAP)
    df = df.dropna(subset=["_label"])
    df = df.rename(columns={k:v for k,v in CIC_MAP.items() if k in df.columns})
    df = add_derived(df)
    for f in fn:
        if f not in df.columns: df[f]=0.0
    if n and len(df)>n:
        df = df.groupby("_label",group_keys=False).apply(
            lambda x: x.sample(min(len(x),n//df["_label"].nunique()),random_state=42))
    X = df[fn].fillna(0).replace([np.inf,-np.inf],0)
    y = df["_label"].values
    yp = model.predict(X)
    pb = model.predict_proba(X).max(axis=1)
    run_report(y, yp, pb)

def test_synthetic(model, fn):
    np.random.seed(42); N=200
    rows,labels=[],[]
    def row(**kw): r={f:0.0 for f in fn}; r.update(kw); return r

    for _ in range(N):
        rows.append(row(flow_pkts_s=np.random.uniform(500,5000),syn_flag_cnt=np.random.randint(50,500),
            flow_byts_s=np.random.uniform(50000,500000),flow_duration=np.random.uniform(0.1,2),
            tot_fwd_pkts=np.random.randint(100,1000),pkt_len_mean=np.random.uniform(40,80),
            syn_ratio=np.random.uniform(0.8,1.0),fwd_pkts_s=np.random.uniform(400,4500)))
        labels.append("DDoS")
    for _ in range(N):
        rows.append(row(flow_duration=np.random.uniform(0.001,0.5),syn_flag_cnt=np.random.randint(1,3),
            rst_flag_cnt=np.random.randint(0,2),tot_fwd_pkts=np.random.randint(1,5),
            pkt_len_mean=np.random.uniform(40,60),rst_ratio=np.random.uniform(0.3,0.8)))
        labels.append("PortScan")
    for _ in range(N):
        rows.append(row(flow_iat_mean=np.random.uniform(100000,500000),
            flow_iat_std=np.random.uniform(1000,10000),flow_pkts_s=np.random.uniform(2,30),
            tot_fwd_pkts=np.random.randint(10,100),pkt_len_mean=np.random.uniform(200,600),
            ack_flag_cnt=np.random.randint(5,50),payload_ratio=np.random.uniform(0.5,0.9)))
        labels.append("BruteForce")
    for _ in range(N):
        rows.append(row(payload_ratio=np.random.uniform(0.85,1.0),
            pkt_len_mean=np.random.uniform(300,1200),pkt_len_max=np.random.uniform(800,1460),
            flow_pkts_s=np.random.uniform(1,15),bytes_per_pkt=np.random.uniform(400,1200)))
        labels.append("SQLi")
    for _ in range(N):
        rows.append(row(payload_ratio=np.random.uniform(0.8,1.0),
            pkt_len_mean=np.random.uniform(200,900),pkt_len_max=np.random.uniform(500,1200),
            flow_pkts_s=np.random.uniform(1,10),bytes_per_pkt=np.random.uniform(250,900)))
        labels.append("XSS")
    for _ in range(N):
        rows.append(row(flow_pkts_s=np.random.uniform(0.1,50),flow_byts_s=np.random.uniform(100,50000),
            flow_iat_mean=np.random.uniform(50000,2000000),pkt_len_mean=np.random.uniform(100,800),
            ack_flag_cnt=np.random.randint(1,20),payload_ratio=np.random.uniform(0.3,0.7)))
        labels.append("BENIGN")

    X = pd.DataFrame(rows)[fn].fillna(0)
    y = np.array(labels)
    yp = model.predict(X)
    pb = model.predict_proba(X).max(axis=1)
    print("\n🧪 합성 데이터 테스트 (각 클래스 200개)")
    run_report(y, yp, pb)
    print("\n⚠️  합성 데이터는 근사치입니다. CICIDS2017 CSV로 실제 검증 권장.")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--csv",help="CICIDS2017 CSV 경로")
    parser.add_argument("--synthetic",action="store_true",help="합성 데이터로 즉시 테스트")
    parser.add_argument("--sample",type=int,default=5000,help="CSV 샘플 수")
    args=parser.parse_args()

    print("🔧 모델 로드...")
    model,fn=load_model()
    print(f"   피처 {len(fn)}개 | 클래스: {list(model.classes_)}")

    if args.csv:
        test_csv(args.csv,model,fn,args.sample)
    elif args.synthetic:
        test_synthetic(model,fn)
    else:
        print("\n사용법:")
        print("  즉시 테스트:  python3 test_model.py --synthetic")
        print("  CSV 테스트:   python3 test_model.py --csv <파일경로>")
        print("\nCICIDS2017 다운로드 (Kaggle 로그인 필요):")
        print("  https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset")
        print("  추천 파일: Wednesday-workingHours.pcap_ISCX.csv (DDoS/PortScan/BENIGN)")
        print("  또는:      Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
