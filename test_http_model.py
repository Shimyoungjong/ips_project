#!/usr/bin/env python3
"""
IPS HTTP(SQLi/XSS) 모델 성능 테스트 스크립트
- pj/model/main.py의 extract_http_features()를 그대로 복제해서 사용
- HttpParamsDataset(Morzeux)으로 검증: https://github.com/Morzeux/HttpParamsDataset
  컬럼: payload,length,attack_type,label  (label: norm / anom, attack_type: norm/sqli/xss/cmdi/path-traversal)

사용법:
  합성 데이터 즉시 테스트:
    python3 test_http_model.py --synthetic
  HttpParamsDataset CSV 테스트 (payload_full.csv 또는 payload_test.csv 다운로드 후):
    python3 test_http_model.py --csv payload_full.csv
"""

import argparse, sys
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

MODEL_DIR = Path(__file__).parent / "models"


def load_model():
    # main.py가 joblib.dump()로 모델을 저장하므로 joblib.load()로 읽어야 함.
    # plain pickle.load()를 쓰면 "_pickle.UnpicklingError: STACK_GLOBAL requires str" 발생.
    model = joblib.load(MODEL_DIR / "rf_model_http.pkl")
    feature_names = list(joblib.load(MODEL_DIR / "http_feature_names.pkl"))
    return model, feature_names


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


# HttpParamsDataset의 attack_type → 우리 모델의 클래스명 매핑
# rf_model_http는 main.py에서 SQLi/XSS만 다루도록 학습되어 있으므로,
# cmdi/path-traversal은 우리 모델 입장에서 "알 수 없는 공격"이라 기준 레이블이 모호함.
# 일단 정보용으로 남겨두고, 모델 클래스와 교차되는 norm/sqli/xss만 정확도 채점에 사용.
ATTACK_MAP = {
    "norm": "BENIGN",
    "sqli": "SQLi",
    "xss":  "XSS",
}


def run_report(y_true, y_pred, proba, model_classes):
    from sklearn.metrics import classification_report, accuracy_score
    acc = accuracy_score(y_true, y_pred)
    print(f"\n{'=' * 55}")
    print(f"  전체 정확도 : {acc * 100:.2f}%")
    print(f"  평균 신뢰도 : {proba.mean() * 100:.2f}%")
    print(f"{'=' * 55}")
    print(classification_report(y_true, y_pred, zero_division=0))
    print("클래스별 상세:")
    for cls in sorted(set(y_true)):
        m = y_true == cls
        print(f"  {cls:<10} 정확도:{(y_pred[m] == cls).mean() * 100:5.1f}%  신뢰도:{proba[m].mean() * 100:5.1f}%  n={m.sum()}")


def test_csv(path, model, fn, n=8000):
    print(f"\n📂 {path}")
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()

    if "payload" not in df.columns:
        sys.exit("❌ 'payload' 컬럼을 찾을 수 없음 (HttpParamsDataset 형식이 맞는지 확인하세요)")

    attack_col = "attack_type" if "attack_type" in df.columns else ("label" if "label" in df.columns else None)
    if attack_col is None:
        sys.exit("❌ 'attack_type'/'label' 컬럼을 찾을 수 없음")

    df["_label"] = df[attack_col].astype(str).str.strip().map(ATTACK_MAP)
    skipped = df["_label"].isna().sum()
    if skipped:
        others = df.loc[df["_label"].isna(), attack_col].unique()
        print(f"  ⚠️  모델이 다루지 않는 공격 유형 {skipped}건 제외: {list(others)} (cmdi/path-traversal 등)")
    df = df.dropna(subset=["_label"])
    df["payload"] = df["payload"].astype(str)

    if n and len(df) > n:
        df = df.groupby("_label", group_keys=False).apply(
            lambda x: x.sample(min(len(x), n // df["_label"].nunique()), random_state=42))

    print(f"  샘플 {len(df)}건으로 피처 추출 중...")
    feats = df["payload"].apply(extract_http_features).apply(pd.Series)
    for f in fn:
        if f not in feats.columns:
            feats[f] = 0
    X = feats[fn].fillna(0)
    y = df["_label"].values

    yp = model.predict(X)
    pb = model.predict_proba(X).max(axis=1)
    run_report(y, yp, pb, model.classes_)


def test_synthetic(model, fn):
    samples = {
        "BENIGN": [
            "hello world", "john.doe@example.com", "서울시 강남구",
            "2024-01-15", "search query text", "12345",
            "product_name=laptop&qty=2", "username123",
        ],
        "SQLi": [
            "1' OR '1'='1", "admin'--", "1 UNION SELECT username,password FROM users",
            "1; DROP TABLE users;--", "' OR 1=1#",
            "1' AND SLEEP(5)--", "1 OR 1=1 UNION SELECT NULL,NULL,version()--",
        ],
        "XSS": [
            "<script>alert('xss')</script>", "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>", "<iframe src=javascript:alert(1)>",
            "<body onload=alert(document.cookie)>", "javascript:alert(1)",
        ],
    }
    rows, labels = [], []
    for label, payloads in samples.items():
        for p in payloads:
            rows.append(extract_http_features(p))
            labels.append(label)

    X = pd.DataFrame(rows)
    for f in fn:
        if f not in X.columns:
            X[f] = 0
    X = X[fn].fillna(0)
    y = np.array(labels)

    yp = model.predict(X)
    pb = model.predict_proba(X).max(axis=1)
    print(f"\n🧪 합성 페이로드 테스트 ({len(y)}건: BENIGN/SQLi/XSS 예시 문자열)")
    run_report(y, yp, pb, model.classes_)
    print("\n⚠️  합성 데이터는 손으로 적은 예시일 뿐입니다. HttpParamsDataset CSV로 실제 검증을 권장합니다.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", help="HttpParamsDataset CSV 경로 (payload_full.csv 등)")
    parser.add_argument("--synthetic", action="store_true", help="합성 페이로드로 즉시 테스트")
    parser.add_argument("--sample", type=int, default=8000, help="CSV 샘플 수(클래스당 분배)")
    args = parser.parse_args()

    print("🔧 모델 로드...")
    model, fn = load_model()
    print(f"   피처 {len(fn)}개 | 클래스: {list(model.classes_)}")

    if args.csv:
        test_csv(args.csv, model, fn, args.sample)
    elif args.synthetic:
        test_synthetic(model, fn)
    else:
        print("\n사용법:")
        print("  즉시 테스트:  python3 test_http_model.py --synthetic")
        print("  CSV 테스트:   python3 test_http_model.py --csv payload_full.csv")
        print("\nHttpParamsDataset 다운로드 (로그인 불필요, 공개 GitHub):")
        print("  https://github.com/Morzeux/HttpParamsDataset")
        print("  추천 파일: payload_full.csv (norm/sqli/xss/cmdi/path-traversal 전체)")
        print("  주의: cmdi/path-traversal 라벨은 현재 모델이 학습하지 않은 유형이라 평가에서 자동 제외됩니다.")
