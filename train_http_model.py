#!/usr/bin/env python3
"""
HTTP(SQLi/XSS) 탐지 모델 재학습 스크립트
- 데이터: Morzeux/HttpParamsDataset (http_dataset/payload_train.csv, payload_test.csv)
- 피처: pj/model/main.py의 extract_http_features()와 100% 동일하게 유지
- cmdi/path-traversal 클래스는 기존 배포 모델(BENIGN/SQLi/XSS 3클래스) 범위를 넘어서므로 제외
"""

import os
import time
import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

IPS_HOME   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = os.path.join(IPS_HOME, "http_dataset")
MODEL_DIR  = os.path.join(IPS_HOME, "models")

LABEL_MAP = {"norm": "BENIGN", "sqli": "SQLi", "xss": "XSS"}


# pj/model/main.py의 extract_http_features()와 100% 동일하게 유지할 것
def extract_http_features(payload: str) -> dict:
    p = payload.lower()
    return {
        "length":        len(payload),
        "single_quote":  payload.count("'"),
        "double_quote":  payload.count('"'),
        "dash_dash":     payload.count('--'),
        "semicolon":     payload.count(';'),
        "equal_sign":    payload.count('='),
        "space_count":   payload.count(' '),
        "pct_encoded":   payload.count('%'),
        "kw_select":     int('select' in p),
        "kw_union":      int('union' in p),
        "kw_insert":     int('insert' in p),
        "kw_drop":       int('drop' in p),
        "kw_delete":     int('delete' in p),
        "kw_update":     int('update' in p),
        "kw_or":         int(' or ' in p),
        "kw_and":        int(' and ' in p),
        "kw_where":      int('where' in p),
        "kw_from":       int('from' in p),
        "kw_sleep":      int('sleep' in p),
        "kw_benchmark":  int('benchmark' in p),
        "tag_script":    int('<script' in p),
        "tag_img":       int('<img' in p),
        "tag_svg":       int('<svg' in p),
        "tag_iframe":    int('<iframe' in p),
        "attr_onerror":  int('onerror' in p),
        "attr_onload":   int('onload' in p),
        "attr_onclick":  int('onclick' in p),
        "js_alert":      int('alert' in p),
        "js_document":   int('document' in p),
        "js_javascript": int('javascript' in p),
        "angle_bracket": payload.count('<') + payload.count('>'),
        "special_total": sum(1 for c in payload if c in "\"'<>;=(){}[]"),
    }


def load_split(csv_path):
    df = pd.read_csv(csv_path)
    df = df[df["attack_type"].isin(LABEL_MAP.keys())].copy()
    df["payload"] = df["payload"].fillna("").astype(str)
    y = df["attack_type"].map(LABEL_MAP)
    feats = df["payload"].apply(extract_http_features).apply(pd.Series)
    return feats, y


print("📥 데이터 로드...")
X_train, y_train = load_split(os.path.join(DATA_DIR, "payload_train.csv"))
X_test,  y_test  = load_split(os.path.join(DATA_DIR, "payload_test.csv"))
FEATURE_NAMES = list(X_train.columns)
print(f"✅ 학습: {len(X_train):,}행 / 테스트: {len(X_test):,}행 / 피처: {len(FEATURE_NAMES)}개")
print(f"✅ 클래스 분포(학습):\n{y_train.value_counts()}\n")

param_dist = {
    'n_estimators':          [200, 300, 400, 500],
    'max_depth':             [10, 15, 20, 25, None],
    'min_samples_split':     [2, 3, 5, 10],
    'min_samples_leaf':      [1, 2, 4],
    'max_features':          ['sqrt', 'log2', 0.3, 0.5],
    'class_weight':          [None, 'balanced'],
}

print("🔍 파라미터 튜닝 중... (n_iter=20, cv=5)")
start = time.time()
search = RandomizedSearchCV(
    RandomForestClassifier(random_state=42, n_jobs=-1),
    param_distributions=param_dist,
    n_iter=20, cv=5,
    scoring='f1_weighted',
    random_state=42, n_jobs=-1, verbose=1,
)
search.fit(X_train, y_train)
print(f"\n✅ 최적 파라미터: {search.best_params_}")
print(f"✅ CV F1: {search.best_score_:.4f}")

model = search.best_estimator_
y_pred = model.predict(X_test)
print(f"\n⏱️ 소요 시간: {(time.time()-start):.1f}초")
print(f"\n📊 평가 결과 (held-out test set, {len(X_test):,}건):")
print(f"전체 정확도: {accuracy_score(y_test, y_pred):.4f}")
print(classification_report(y_test, y_pred))

cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d',
            xticklabels=model.classes_, yticklabels=model.classes_, cmap='Blues')
plt.title('Confusion Matrix - HTTP model v2 (Morzeux HttpParamsDataset)')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig(os.path.join(MODEL_DIR, 'confusion_matrix_http_v2.png'))
plt.close()

joblib.dump(model, os.path.join(MODEL_DIR, 'rf_model_http_v2.pkl'))
joblib.dump(FEATURE_NAMES, os.path.join(MODEL_DIR, 'http_feature_names_v2.pkl'))

print(f"\n✅ 새 모델 저장 완료 (기존 모델은 그대로 둠, _v2로 저장): {MODEL_DIR}")
print(f"  탐지 클래스: {list(model.classes_)}")
