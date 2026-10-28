// 배포 모델에서 뽑은 고정 정보 (2026-10-28)
// 중요도: rf_model_hybrid.pkl / rf_model_http_v4.pkl 의 feature_importances_ 상위 10개
// 성능: models/compare_flow_results.json, HTTP는 train_http_model.py 테스트셋 + 처음 보는 공개 페이로드 테스트
// 모델을 다시 학습하면 이 값도 다시 뽑아야 함

export const MODELS = {
  flow: {
    name: '흐름 모델',
    algo: 'Random Forest · 트리 200개',
    input: '패킷 흐름 통계 59개',
    classes: ['BENIGN', 'BruteForce', 'DoS/DDoS', 'PortScan'],
    data: 'CIC-IDS2017 수정판(공개) + 직접 캡처한 공격 트래픽',
    metrics: [
      ['시연 환경 평가 정확도', '99.87%'],
      ['공개 데이터 평가 정확도', '99.97%'],
    ],
    features: [
      ['최소 패킷 길이', 0.0768], ['SYN 플래그 비율', 0.0579], ['RST 플래그 비율', 0.0442],
      ['초당 응답 패킷 수', 0.0430], ['요청 방향 최대 패킷 길이', 0.0428], ['헤더 비율', 0.0364],
      ['평균 패킷 길이', 0.0349], ['요청 방향 평균 패킷 길이', 0.0341], ['평균 패킷 크기', 0.0309],
      ['최대 패킷 간격', 0.0294],
    ],
  },
  http: {
    name: 'HTTP 모델',
    algo: 'Random Forest · 트리 400개',
    input: '요청 값 문자 특징 32개',
    classes: ['BENIGN', 'SQLi', 'XSS'],
    data: 'HttpParamsDataset(공개) + FWAF 정상 웹 쿼리(공개)',
    metrics: [
      ['테스트셋 정확도', '99.96%'],
      ['처음 보는 XSS 탐지율', '100%'],
      ['처음 보는 SQLi 탐지율', '80.7%'],
      ['일반 문장 오탐률', '3.2%'],
    ],
    features: [
      ['공백 개수', 0.3769], ['SELECT 키워드', 0.1987], ['특수문자 총개수', 0.1600],
      ['작은따옴표 개수', 0.0685], ['AND 키워드', 0.0353], ['큰따옴표 개수', 0.0351],
      ['꺾쇠(<>) 개수', 0.0305], ['SQL 주석(--) 개수', 0.0233], ['OR 키워드', 0.0204],
      ['입력 길이', 0.0117],
    ],
  },
};

// 같은 평가 데이터(직접 캡처 시간순 25%, CIC 25%)로 비교한 흐름 모델 3종
export const FLOW_COMPARISON = [
  ['직접 캡처만', '99.89%', '45.59%'],
  ['공개 데이터만', '24.33%', '99.99%'],
  ['하이브리드 (채택)', '99.87%', '99.97%'],
];

// 하이브리드 흐름 모델 · 직접 캡처 평가분 혼동 행렬 (행: 실제, 열: 예측)
export const CONFUSION = {
  classes: ['BENIGN', 'BruteForce', 'DoS/DDoS', 'PortScan'],
  matrix: [
    [17420, 67, 0, 0],
    [22, 17449, 0, 0],
    [1, 0, 17914, 0],
    [0, 0, 0, 17903],
  ],
};

export const RESPONSE_LEVELS = [
  ['LOW', '40% 이상', '로그 기록과 모니터링'],
  ['MEDIUM', '55% 이상', '연결 속도 제한 (초당 5회)'],
  ['HIGH', '65% 이상', '웹서버 접속을 허니팟으로 우회'],
  ['CRITICAL', '80% 이상 + 지속', '완전 차단, 10분 후 자동 해제'],
];

// 탐지 유형 → 판정한 모델
export const modelOf = (type) => (['SQLi', 'XSS', 'CMDi', 'PathTraversal'].includes(type) ? 'http' : 'flow');
