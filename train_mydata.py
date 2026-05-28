import pandas as pd
import numpy as np
import glob
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import classification_report, confusion_matrix
import time

# ==================== 설정 ====================
DATA_DIR  = os.path.expanduser("~/ips_project/MachineLearningCSV")
MODEL_DIR = os.path.expanduser("~/ips_project/models")
SAMPLE_PER_CLASS = 68000
TEST_SIZE        = 0.25
EXCLUDE_CLASSES  = []
# ==============================================

os.makedirs(MODEL_DIR, exist_ok=True)

# ==================== 데이터 로드 ====================
print("📂 내 수집 데이터 로드 중...")
csv_files = glob.glob(os.path.join(DATA_DIR, "*_labeled.csv"))
print(f"총 {len(csv_files)}개 파일 발견!\n")

dfs = []
for f in csv_files:
    fname = os.path.basename(f)
    try:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        if 'label' not in df.columns:
            print(f"  ⚠️ 라벨 없음 스킵: {fname}")
            continue
        df['label'] = df['label'].astype(str).str.strip()
        df = df[~df['label'].isin(EXCLUDE_CLASSES)]
        df = df.dropna(subset=['label'])
        print(f"  ✅ {fname}: {len(df):,}행 | 클래스: {df['label'].unique()}")
        dfs.append(df)
    except Exception as e:
        print(f"  ❌ {fname} 오류: {e}")

df_all = pd.concat(dfs, ignore_index=True)
print(f"\n✅ 전체: {len(df_all):,}행")
print(f"클래스 분포:\n{df_all['label'].value_counts()}\n")

# ==================== 샘플링 ====================
print("📊 클래스별 샘플링 중...")
sampled = []
for label, group in df_all.groupby('label'):
    n = min(len(group), SAMPLE_PER_CLASS)
    sampled.append(group.sample(n, random_state=42))
    print(f"  {label}: {n:,}개")

df_sampled = pd.concat(sampled, ignore_index=True)
print(f"\n✅ 샘플링 후 총: {len(df_sampled):,}행\n")

# ==================== 피처 준비 ====================
drop_cols = ['label', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
             'protocol', 'timestamp']
drop_cols = [c for c in drop_cols if c in df_sampled.columns]

X_all = df_sampled.drop(columns=drop_cols)
y_all = df_sampled['label']

X_all = X_all.apply(pd.to_numeric, errors='coerce')
X_all = X_all.replace([np.inf, -np.inf], np.nan).fillna(0)

# 기존 파생 피처
X_all['win_ratio']         = X_all['init_fwd_win_byts'] / (X_all['init_bwd_win_byts'] + 1)
X_all['payload_ratio']     = X_all['totlen_fwd_pkts']   / (X_all['totlen_bwd_pkts']   + 1)
X_all['fwd_bwd_pkt_ratio'] = X_all['tot_fwd_pkts']      / (X_all['tot_bwd_pkts']      + 1)
X_all['pkt_len_range']     = X_all['pkt_len_max']        - X_all['pkt_len_min']

# 추가 파생 피처 (BruteForce 구분 강화)
# IAT 변동계수: 브루트포스는 일정한 간격 → CV 낮음
X_all['iat_cv']      = X_all['flow_iat_std']  / (X_all['flow_iat_mean']  + 1)
X_all['fwd_iat_cv']  = X_all['fwd_iat_std']   / (X_all['fwd_iat_mean']   + 1)
# 연결 당 패킷 수: 브루트포스는 짧은 연결 반복 → 낮음
X_all['pkt_per_flow'] = (X_all['tot_fwd_pkts'] + X_all['tot_bwd_pkts']) / (X_all['flow_duration'] + 1)
# SYN/FIN 비율: 브루트포스는 연결/해제 반복 → 높음
total_pkts = X_all['tot_fwd_pkts'] + X_all['tot_bwd_pkts'] + 1
X_all['syn_ratio']   = X_all['syn_flag_cnt']   / total_pkts
X_all['fin_ratio']   = X_all['fin_flag_cnt']   / total_pkts
X_all['rst_ratio']   = X_all['rst_flag_cnt']   / total_pkts
# 활성/유휴 비율: DDoS는 계속 활성 상태
X_all['active_idle_ratio'] = X_all['active_mean'] / (X_all['idle_mean'] + 1)
# 바이트 효율: DDoS는 작은 패킷 대량
X_all['bytes_per_pkt'] = X_all['flow_byts_s'] / (X_all['flow_pkts_s'] + 1)
# 헤더 오버헤드: 브루트포스는 헤더 비율 높음
X_all['header_ratio'] = (X_all['fwd_header_len'] + X_all['bwd_header_len']) / (X_all['totlen_fwd_pkts'] + X_all['totlen_bwd_pkts'] + 1)

X_all = X_all.replace([np.inf, -np.inf], np.nan).fillna(0).clip(-1e15, 1e15)

# ==================== 피처 선택 ====================
TOP_FEATURES = [
    # 패킷 길이
    'init_fwd_win_byts', 'init_bwd_win_byts', 'bwd_seg_size_avg',
    'bwd_pkt_len_mean', 'pkt_len_mean', 'bwd_pkt_len_std', 'pkt_size_avg',
    'fwd_header_len', 'bwd_header_len', 'totlen_fwd_pkts', 'fwd_pkt_len_max',
    'pkt_len_var', 'subflow_fwd_pkts', 'subflow_fwd_byts', 'tot_fwd_pkts',
    'pkt_len_min', 'fwd_seg_size_avg', 'pkt_len_std', 'bwd_pkt_len_max',
    'fwd_pkt_len_mean', 'totlen_bwd_pkts', 'fwd_pkt_len_std',
    'subflow_bwd_byts', 'pkt_len_max',
    # 플로우 통계
    'flow_duration', 'flow_byts_s', 'flow_pkts_s', 'fwd_pkts_s', 'bwd_pkts_s',
    'fwd_act_data_pkts', 'fwd_byts_b_avg', 'down_up_ratio',
    # IAT (패킷 간격) - BruteForce 핵심
    'flow_iat_mean', 'flow_iat_std', 'flow_iat_min', 'flow_iat_max',
    'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_min', 'fwd_iat_tot',
    'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_min',
    # TCP 플래그 - BruteForce/DDoS 핵심
    'syn_flag_cnt', 'fin_flag_cnt', 'rst_flag_cnt',
    'psh_flag_cnt', 'ack_flag_cnt',
    # 활성/유휴
    'active_mean', 'active_std', 'idle_mean', 'idle_std',
    # 파생 피처
    'win_ratio', 'payload_ratio', 'fwd_bwd_pkt_ratio', 'pkt_len_range',
    'iat_cv', 'fwd_iat_cv', 'pkt_per_flow',
    'syn_ratio', 'fin_ratio', 'rst_ratio',
    'active_idle_ratio', 'bytes_per_pkt', 'header_ratio',
]
TOP_FEATURES = [f for f in TOP_FEATURES if f in X_all.columns]
print(f"✅ 피처 수: {len(TOP_FEATURES)}개")
print(f"✅ 클래스: {y_all.unique()}\n")

# ==================== 학습 ====================
X = X_all[TOP_FEATURES]
X_train, X_test, y_train, y_test = train_test_split(
    X, y_all, test_size=TEST_SIZE, random_state=42, stratify=y_all
)
print(f"학습: {len(X_train):,}행 / 테스트: {len(X_test):,}행\n")

param_dist = {
    'n_estimators':        [300, 400, 500, 600],
    'max_depth':           [10, 15, 20, 25, 30, None],
    'min_samples_split':   [2, 3, 5, 10],
    'min_samples_leaf':    [1, 2, 4],
    'max_features':        ['sqrt', 'log2', 0.3, 0.5],
    'class_weight':        [None, 'balanced'],
    'min_impurity_decrease': [0.0, 0.001, 0.01],
}

print("🔍 파라미터 튜닝 중... (n_iter=20, cv=3)")
start = time.time()
search = RandomizedSearchCV(
    RandomForestClassifier(random_state=42, n_jobs=-1),
    param_distributions=param_dist,
    n_iter=20, cv=3,
    scoring='f1_weighted',
    random_state=42, n_jobs=-1, verbose=1
)
search.fit(X_train, y_train)
print(f"\n✅ 최적 파라미터: {search.best_params_}")
print(f"✅ CV F1: {search.best_score_:.4f}")

model = search.best_estimator_
y_pred = model.predict(X_test)
print(f"\n⏱️ 소요 시간: {(time.time()-start)/60:.1f}분")
print(f"\n📊 평가 결과:")
print(classification_report(y_test, y_pred))

# 혼동 행렬
cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d',
            xticklabels=model.classes_, yticklabels=model.classes_, cmap='Blues')
plt.title('Confusion Matrix - RF v2 (More Features)')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, 'confusion_matrix_mydata.png'))
plt.close()

# ==================== 저장 ====================
joblib.dump(model, os.path.join(MODEL_DIR, 'rf_model.pkl'))
joblib.dump(TOP_FEATURES, os.path.join(MODEL_DIR, 'feature_names.pkl'))
joblib.dump(model.classes_, os.path.join(MODEL_DIR, 'classes.pkl'))

print(f"\n✅ 모델 저장 완료!")
print(f"📁 {MODEL_DIR}")
print(f"  탐지 클래스: {list(model.classes_)}")
