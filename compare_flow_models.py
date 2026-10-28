#!/usr/bin/env python3
"""
흐름 모델 3종 분류 성능 비교 — 같은 평가 데이터로 공정 비교
  (1) 직접 캡처만   : MachineLearningCSV 학습분
  (2) 공개 데이터만 : CIC-IDS-2017 improved
  (3) 하이브리드    : CIC-IDS-2017 improved + MachineLearningCSV 학습분
- 직접 캡처 데이터는 클래스별 시간순 75%/25%로 분할 (같은 공격 세션이 학습·평가에 섞이지 않도록)
- 세 모델 모두 같은 피처(59개)와 같은 RandomForest 설정 사용
- 평가: 직접 캡처 평가분(시연 환경) + CIC 평가분(공개 데이터)
결과: models/compare_cm_*.png, models/compare_flow_results.json, models/rf_model_hybrid.pkl
"""

import glob
import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

from train_public_flow import CLASSES, FEATURES, MODEL_DIR, OWN_DIR, add_derived, load_public, save_cm

OWN_TRAIN_RATIO = 0.75
HYBRID_CIC_CAP  = 60000  # 하이브리드에서 CIC 클래스당 최대 (직접 캡처 학습분 ~5만과 비슷한 규모로 맞춤)
TITLES = {"직접 캡처만": "Own captures only", "공개 데이터만": "Public (CIC-IDS-2017) only", "하이브리드": "Hybrid (public + own)"}


def make_rf():
    return RandomForestClassifier(
        n_estimators=200, max_depth=25, min_samples_leaf=2,
        class_weight="balanced_subsample", random_state=42, n_jobs=-1,
    )


def load_own_split():
    train_parts, test_parts = [], []
    for f in glob.glob(os.path.join(OWN_DIR, "*_labeled.csv")):
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        df["label"] = df["label"].astype(str).str.strip()
        df = df[df["label"].isin(CLASSES)]
        if df.empty:
            continue
        df = df.assign(_ts=pd.to_datetime(df["timestamp"], errors="coerce")).sort_values("_ts", kind="stable")
        cut = int(len(df) * OWN_TRAIN_RATIO)
        train_parts.append(df.iloc[:cut])
        test_parts.append(df.iloc[cut:])

    def prep(df):
        y = df["label"].reset_index(drop=True)
        X = df.drop(columns=[c for c in ["label", "_ts", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp"] if c in df.columns])
        X = add_derived(X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0))
        return X[FEATURES].reset_index(drop=True), y

    return prep(pd.concat(train_parts)), prep(pd.concat(test_parts))


def cap_per_class(X, y, cap):
    idx = []
    for label in y.unique():
        li = y.index[y == label]
        idx.extend(li if len(li) <= cap else pd.Series(li).sample(cap, random_state=42))
    return X.loc[idx].reset_index(drop=True), y.loc[idx].reset_index(drop=True)


def evaluate(name, model, X, y, tag):
    pred = model.predict(X)
    rep = classification_report(y, pred, labels=CLASSES, output_dict=True, zero_division=0)
    print(f"\n── {name} → {tag} ({len(X):,}건) 정확도 {accuracy_score(y, pred):.4f} / macro F1 {f1_score(y, pred, labels=CLASSES, average='macro', zero_division=0):.4f}")
    print(pd.crosstab(pd.Series(y, name="실제"), pd.Series(pred, name="예측")).reindex(index=CLASSES, columns=CLASSES, fill_value=0))
    return {
        "accuracy": round(accuracy_score(y, pred), 4),
        "macro_f1": round(f1_score(y, pred, labels=CLASSES, average="macro", zero_division=0), 4),
        "per_class": {c: {k: round(rep[c][k], 4) for k in ("precision", "recall", "f1-score")} for c in CLASSES},
        "confusion": confusion_matrix(y, pred, labels=CLASSES).tolist(),
    }, pred


def main():
    print("📥 직접 캡처 데이터 시간순 분할...")
    (Xo_tr, yo_tr), (Xo_te, yo_te) = load_own_split()
    print(f"  학습 {len(Xo_tr):,} / 평가 {len(Xo_te):,}\n{yo_te.value_counts()}")

    print("\n📥 공개 데이터 로드...")
    Xc, yc = load_public()
    Xc_tr, Xc_te, yc_tr, yc_te = train_test_split(Xc, yc, test_size=0.25, random_state=42, stratify=yc)
    Xc_tr, yc_tr = Xc_tr.reset_index(drop=True), yc_tr.reset_index(drop=True)
    Xc_te, yc_te = Xc_te.reset_index(drop=True), yc_te.reset_index(drop=True)

    Xh_c, yh_c = cap_per_class(Xc_tr, yc_tr, HYBRID_CIC_CAP)
    Xh = pd.concat([Xh_c, Xo_tr], ignore_index=True)
    yh = pd.concat([yh_c, yo_tr], ignore_index=True)

    setups = {
        "직접 캡처만": (Xo_tr, yo_tr),
        "공개 데이터만": (Xc_tr, yc_tr),
        "하이브리드": (Xh, yh),
    }
    results, models = {}, {}
    for name, (X, y) in setups.items():
        print(f"\n🌲 [{name}] 학습 {len(X):,}건...")
        m = make_rf().fit(X, y)
        models[name] = m
        r_own, p_own = evaluate(name, m, Xo_te, yo_te, "직접 캡처 평가분")
        r_cic, _ = evaluate(name, m, Xc_te, yc_te, "CIC 평가분")
        results[name] = {"train_rows": len(X), "own_test": r_own, "cic_test": r_cic}
        save_cm(yo_te, p_own, f"{TITLES[name]} - own captures (time-split test)",
                os.path.join(MODEL_DIR, f"compare_cm_{['own', 'public', 'hybrid'][list(setups).index(name)]}.png"))

    out = {
        "own_test_rows": len(Xo_te), "cic_test_rows": len(Xc_te),
        "own_test_counts": yo_te.value_counts().to_dict(), "classes": CLASSES, "results": results,
    }
    json.dump(out, open(os.path.join(MODEL_DIR, "compare_flow_results.json"), "w"), ensure_ascii=False, indent=1)
    joblib.dump(models["하이브리드"], os.path.join(MODEL_DIR, "rf_model_hybrid.pkl"), compress=3)
    print("\n✅ 저장: models/compare_flow_results.json, models/compare_cm_{own,public,hybrid}.png, models/rf_model_hybrid.pkl")


if __name__ == "__main__":
    main()
