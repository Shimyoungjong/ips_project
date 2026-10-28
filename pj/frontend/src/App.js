import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { ShieldAlert, Activity, BarChart3, Clock, Eye, Trash2, Ban, PieChart, Server, ChevronDown, ChevronUp, Lightbulb, Brain, X } from 'lucide-react';
import bb, { spline, donut } from 'billboard.js';
import 'billboard.js/dist/billboard.css';
import './App.css';
import { MODELS, FLOW_COMPARISON, CONFUSION, RESPONSE_LEVELS, modelOf } from './modelInfo';

const ATTACK_COLORS = {
  BruteForce: '#f97316',
  PortScan:   '#a855f7',
  DDoS:       '#ef4444',
  SQLi:       '#eab308',
  XSS:        '#ec4899',
  Honeypot:   '#06b6d4',
  CMDi:       '#84cc16',
  PathTraversal: '#14b8a6',
};

const TIMELINE_BUCKET_MS = 10 * 1000;   // 10초 단위로 집계
const TIMELINE_WINDOW_MS = 5 * 60 * 1000; // 최근 5분만 표시

const bucketStart = (tsMs) => Math.floor(tsMs / TIMELINE_BUCKET_MS) * TIMELINE_BUCKET_MS;

// 백엔드 타임스탬프 'YYYY-MM-DD HH:MM:SS' -> epoch ms (로컬 타임존 기준)
const parseTimestamp = (ts) => {
  const t = new Date(ts.replace(' ', 'T')).getTime();
  return Number.isNaN(t) ? Date.now() : t;
};

// 모델 신뢰도 -> 위협 레벨 (백엔드 main.py의 LEVEL_MEDIUM/HIGH/CRITICAL과 동일하게 유지)
const LEVEL_MEDIUM = 0.55;
const LEVEL_HIGH = 0.65;
const LEVEL_CRITICAL = 0.80;
const LEVELS = {
  critical: { label: 'Critical', color: '#f43f5e' },
  high:     { label: 'High',     color: '#f97316' },
  medium:   { label: 'Medium',   color: '#eab308' },
  low:      { label: 'Low',      color: '#22c55e' },
  benign:   { label: '정상',      color: '#64748b' },
  suspicious: { label: '미분류',   color: '#a78bfa' }, // 흐름 모델 신뢰도 낮음 — 학습에 없는 공격일 수 있음
};
const threatLevel = (log) => {
  if (log.attack_type === 'Suspicious') return 'suspicious';
  if (!log.is_attack) return 'benign';
  if (log.confidence >= LEVEL_CRITICAL) return 'critical';
  if (log.confidence >= LEVEL_HIGH) return 'high';
  if (log.confidence >= LEVEL_MEDIUM) return 'medium';
  return 'low';
};

// 사이드바 메뉴 = 페이지. 주소 해시(#/blocked 등)로 페이지를 구분해 뒤로 가기·직접 링크가 동작
const PAGES = [
  { id: 'overview', label: '개요', icon: PieChart },
  { id: 'events', label: '탐지 로그', icon: BarChart3 },
  { id: 'advice', label: '대응 권고', icon: Lightbulb },
  { id: 'model', label: '모델 정보', icon: Brain },
  { id: 'blocked', label: '차단 관리', icon: Ban },
  { id: 'watchlist', label: '감시목록', icon: Eye },
  { id: 'server', label: '서버 로그', icon: Server },
];
// 공격 유형별 대응 권고 (탐지 결과에 맞춰 표시하는 정해진 권고문)
const ADVICE = {
  SQLi: { risk: 'high', desc: '입력값에 SQL 구문을 넣어 DB를 조회·변조하는 공격', actions: ['SQL 쿼리를 파라미터 바인딩(Prepared Statement)으로 작성', '입력값 길이·형식 검증과 특수문자 처리', 'DB 계정 권한 최소화, DB 오류 메시지 노출 차단'] },
  XSS: { risk: 'high', desc: '페이지에 악성 스크립트를 심어 사용자 브라우저에서 실행시키는 공격', actions: ['출력할 때 HTML 이스케이프 적용', 'Content-Security-Policy(CSP) 헤더 설정', '쿠키에 HttpOnly·Secure 속성 지정'] },
  DDoS: { risk: 'high', desc: '대량의 요청으로 서비스를 마비시키는 공격', actions: ['출발지 IP별 요청 속도 제한(rate limit)', '반복 공격 IP 차단 유지, 상위 방화벽·CDN 차단 요청', '연결 타임아웃·동시 연결 수 상한 조정'] },
  PortScan: { risk: 'medium', desc: '열린 포트를 찾아 다음 공격을 준비하는 정찰 행위', actions: ['서비스에 필요 없는 포트 닫기', '스캔 IP를 감시목록에 올려 후속 공격 주시', '외부에 노출되는 서비스 버전 정보 숨기기'] },
  BruteForce: { risk: 'high', desc: '비밀번호를 반복 대입해 로그인하려는 공격', actions: ['로그인 실패 횟수 제한과 일시 잠금', 'SSH는 키 인증 사용, 관리자 로그인에 2단계 인증 적용', '기본 계정명·약한 비밀번호 변경'] },
  CMDi: { risk: 'high', desc: '입력값으로 서버 운영체제 명령을 실행시키는 공격', actions: ['사용자 입력을 셸 명령에 직접 넣지 않기', '허용 목록 기반 입력 검증', '웹 서버 실행 계정 권한 최소화'] },
  PathTraversal: { risk: 'medium', desc: '../ 등으로 허용되지 않은 파일에 접근하는 공격', actions: ['경로를 정규화한 뒤 허용 디렉터리 안인지 확인', '사용자 입력으로 파일명을 직접 지정하지 않기', '민감 파일 접근 권한 제한'] },
  Honeypot: { risk: 'medium', desc: '허니팟에 접근한 IP — 공격 의도가 높은 대상', actions: ['해당 IP 감시목록 유지, 정상 서버 접근 시 즉시 차단 검토', '허니팟 로그로 공격 패턴 분석'] },
};
const ADVICE_DEFAULT = { risk: 'medium', desc: '분류된 공격 유형', actions: ['해당 IP 접근 기록 확인', '반복 시 차단 유지 검토'] };

const pageFromHash = () => {
  const id = window.location.hash.replace('#/', '');
  return PAGES.some(pg => pg.id === id) ? id : 'overview';
};

// 화면 표시용 유형 이름 (모델 클래스명은 그대로). 공격자 한 대면 엄밀히 DoS라 'DoS/DDoS'로 표시
const TYPE_LABELS = { DDoS: 'DoS/DDoS', Suspicious: '미분류 의심' };
const typeLabel = (t) => TYPE_LABELS[t] || t;

const ROW_HIGHLIGHT_MS = 2000; // 새 탐지 행 하이라이트 유지 시간

const styles = {
  container: { padding: '24px 28px', backgroundColor: '#0f172a', minHeight: '100vh', color: '#f1f5f9', fontFamily: "'Pretendard', sans-serif", boxSizing: 'border-box' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '20px', borderBottom: '1px solid #334155', paddingBottom: '16px' },
  card: { backgroundColor: '#1e293b', padding: '20px 24px', borderRadius: '16px', border: '1px solid #334155', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', minWidth: 0 },
  cardTitle: { display: 'flex', alignItems: 'center', gap: '10px', color: '#94a3b8', fontSize: '14px', fontWeight: 'bold' },
  kpiValue: (color) => ({ fontSize: '34px', fontWeight: 'bold', color, marginTop: '8px', lineHeight: 1.1 }),
  kpiSub: { fontSize: '12px', color: '#64748b', marginTop: '6px' },
  panel: { backgroundColor: '#1e293b', borderRadius: '16px', border: '1px solid #334155', overflow: 'hidden', display: 'flex', flexDirection: 'column', minWidth: 0 },
  panelHeader: { padding: '14px 20px', borderBottom: '1px solid #334155', fontWeight: 'bold', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' },
  panelHint: { fontSize: '12px', color: '#64748b', fontWeight: 'normal' },
  table: { width: '100%', borderCollapse: 'collapse' },
  th: { position: 'sticky', top: 0, zIndex: 1, backgroundColor: '#334155', padding: '10px 14px', textAlign: 'left', fontSize: '13px', color: '#94a3b8' },
  td: { padding: '10px 14px', borderBottom: '1px solid #334155', fontSize: '14px' },
  badge: (blocked) => ({ padding: '4px 10px', borderRadius: '20px', fontSize: '12px', fontWeight: 'bold', backgroundColor: blocked ? '#166534' : '#991b1b', color: '#f8fafc', whiteSpace: 'nowrap' }),
  countBadge: (bg) => ({ backgroundColor: bg, color: '#fff', borderRadius: '10px', padding: '1px 8px', fontSize: '12px' }),
  listItem: { padding: '12px 20px', borderBottom: '1px solid #334155' },
  empty: { padding: '28px', textAlign: 'center', color: '#475569', fontSize: '14px' },
  smallBtn: (color) => ({ padding: '3px 9px', borderRadius: '6px', border: '1px solid #475569', background: 'none', color, cursor: 'pointer', fontSize: '12px' }),
  headerBtn: (bg, color = '#fff') => ({ padding: '8px 18px', borderRadius: '8px', border: 'none', backgroundColor: bg, color, fontWeight: 'bold', cursor: 'pointer', fontSize: '14px' }),
  pill: (bg, color) => ({ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12px', fontWeight: 'normal', padding: '4px 10px', borderRadius: '20px', backgroundColor: bg, color }),
  threatBadge: (level) => {
    const colors = { high: '#7f1d1d', medium: '#78350f', low: '#14532d', critical: '#4c0519' };
    const textColors = { high: '#fca5a5', medium: '#fcd34d', low: '#86efac', critical: '#f9a8d4' };
    return { padding: '3px 10px', borderRadius: '20px', fontSize: '12px', fontWeight: 'bold', backgroundColor: colors[level] || '#1e293b', color: textColors[level] || '#94a3b8' };
  },
};

function App() {
  const [serverLogsOpen, setServerLogsOpen] = useState(true);
  const [page, setPage] = useState(pageFromHash);
  const [unacked, setUnacked] = useState(0); // 확인 안 한 Critical 경고 수 (0보다 크면 테두리가 계속 깜박임)
  const [logs, setLogs] = useState([]);
  const [serverLogs, setServerLogs] = useState([]);
  const [stats, setStats] = useState({ total: 0, benign: 0, attack: 0, status: "연결 대기 중..." });
  const [currentTime, setCurrentTime] = useState(new Date().toLocaleTimeString());
  const [connected, setConnected] = useState(false);
  const [ipsRunning, setIpsRunning] = useState(false);
  const [timeline, setTimeline] = useState([]); // [{ t: epochMs, counts: { SQLi: n, ... } }] - 창 전체를 빈틈없이 채운 배열
  const [watchlist, setWatchlist] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);
  const [typeCounts, setTypeCounts] = useState({}); // 유형별 공격 탐지 건수 (/stats/by_type)
  const [selected, setSelected] = useState(null); // 상세 모달에 띄운 탐지 항목
  const chartContainerRef = useRef(null);
  const chartInstanceRef = useRef(null);
  const donutContainerRef = useRef(null);
  const donutInstanceRef = useRef(null);
  const donutBoundElRef = useRef(null); // 도넛이 그려진 DOM 요소 (화면 전환으로 바뀌면 새로 생성)
  const rowArrivedRef = useRef(new Map()); // 로그 행 key -> 처음 화면에 나타난 시각 (하이라이트용)
  const logsSeededRef = useRef(false);     // 최초 로드분은 하이라이트하지 않음
  const timelineSeededRef = useRef(false);
  const bucketMapRef = useRef(new Map()); // 실제 이벤트만 저장하는 원본 데이터 (t -> { counts })

  // bucketMapRef(실제 이벤트)를 기준으로, 최근 5분 창을 10초 간격으로 빈틈없이 채운 배열을 만들어 화면에 반영.
  // 이게 없으면 이벤트가 드문드문 있을 때 그 사이가 그냥 직선으로 이어져서 꺾은선이 아니라 사선처럼 보임.
  const rebuildTimeline = () => {
    const now = Date.now();
    const nowBucket = bucketStart(now);
    const startBucket = nowBucket - TIMELINE_WINDOW_MS + TIMELINE_BUCKET_MS;
    for (const key of bucketMapRef.current.keys()) {
      if (key < startBucket) bucketMapRef.current.delete(key);
    }
    const arr = [];
    for (let t = startBucket; t <= nowBucket; t += TIMELINE_BUCKET_MS) {
      arr.push({ t, counts: bucketMapRef.current.get(t) || {} });
    }
    setTimeline(arr);
  };

  // 새 탐지 이벤트를 해당 시간 버킷에 누적
  const addTimelineEvent = (attackType, tsMs) => {
    const bStart = bucketStart(tsMs);
    const counts = bucketMapRef.current.get(bStart) || {};
    bucketMapRef.current.set(bStart, { ...counts, [attackType]: (counts[attackType] || 0) + 1 });
    rebuildTimeline();
  };

  useEffect(() => {
    const onHash = () => setPage(pageFromHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  const go = (id) => { window.location.hash = `/${id}`; };

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') setSelected(null); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(timer);
  }, []);

  const fetchWatchlist = async () => {
    try {
      const res = await axios.get('http://localhost:8000/watchlist');
      setWatchlist(res.data);
    } catch {}
  };

  const fetchBlockedIps = async () => {
    try {
      const res = await axios.get('http://localhost:8000/blocked_ips');
      setBlockedIps(res.data);
    } catch {}
  };

  const handleBlockedDecision = async (ip, action) => {
    await axios.post('http://localhost:8000/blocked_ips/decide', { ip, action });
    fetchBlockedIps();
  };

  const fetchData = async () => {
    try {
      const [logRes, statRes, statusRes, serverLogRes, typeRes] = await Promise.all([
        axios.get('http://localhost:8000/logs'),
        axios.get('http://localhost:8000/stats'),
        axios.get('http://localhost:8000/ips_status'),
        axios.get('http://localhost:8000/server_logs'),
        axios.get('http://localhost:8000/stats/by_type'),
      ]);
      setLogs(logRes.data);
      setStats(statRes.data);
      setIpsRunning(statusRes.data.running);
      setServerLogs(serverLogRes.data.reverse());
      setTypeCounts(typeRes.data);
      setConnected(true);

      // 최초 로드 시 최근 5분 내 로그로 타임라인 초기값 구성 (이후엔 웹소켓으로만 갱신)
      if (!timelineSeededRef.current) {
        timelineSeededRef.current = true;
        const now = Date.now();
        for (const log of logRes.data) {
          if (!log.is_attack) continue;
          const tsMs = parseTimestamp(log.timestamp);
          if (tsMs < now - TIMELINE_WINDOW_MS) continue;
          const bStart = bucketStart(tsMs);
          const counts = bucketMapRef.current.get(bStart) || {};
          bucketMapRef.current.set(bStart, { ...counts, [log.attack_type]: (counts[log.attack_type] || 0) + 1 });
        }
        rebuildTimeline();
      }
    } catch {
      setConnected(false);
    }
  };

  const handleStart = async () => {
    await axios.post('http://localhost:8000/start');
    setIpsRunning(true);
    setStats({ total: 0, benign: 0, attack: 0, status: "실시간 보호 중" });
    setLogs([]);
    setServerLogs([]);
    setWatchlist([]);
    bucketMapRef.current.clear();
    setTimeline([]);
    timelineSeededRef.current = true; // 시작 직후엔 과거 로그로 재시딩하지 않음
    setBlockedIps([]);
    setTypeCounts({});
    setUnacked(0);
  };

  const handleStop = async () => {
    await axios.post('http://localhost:8000/stop');
    setIpsRunning(false);
  };

  const handleEmergencyReset = async () => {
    if (!window.confirm('⚠️ 모든 차단/감시목록을 해제합니다. 계속하시겠습니까?')) return;
    await axios.post('http://localhost:8000/emergency_reset');
    alert('✅ 긴급 해제 완료! 모든 차단이 풀렸습니다.');
  };

  const handleRemoveWatchlist = async (ip) => {
    await axios.post('http://localhost:8000/watchlist/remove', { ip });
    fetchWatchlist();
  };

  // 5분 창을 계속 앞으로 밀어주기 위해, 새 이벤트가 없어도 주기적으로 창을 다시 채움
  useEffect(() => {
    const trimTimer = setInterval(rebuildTimeline, 10 * 1000);
    return () => clearInterval(trimTimer);
  }, []);

  useEffect(() => {
    if (!chartContainerRef.current) return;

    const types = [...new Set(timeline.flatMap(b => Object.keys(b.counts)))];

    // 데이터가 아직 없으면(공격 0건) 차트 생성/갱신 자체를 건너뜀.
    if (types.length === 0) {
      if (chartInstanceRef.current) {
        try { chartInstanceRef.current.destroy(); } catch (e) { /* 무시 */ }
        chartInstanceRef.current = null;
      }
      return;
    }

    const xColumn = ['x', ...timeline.map(b => new Date(b.t))];
    const typeColumns = types.map(t => [t, ...timeline.map(b => b.counts[t] || 0)]);
    const colors = Object.fromEntries(types.map(t => [t, ATTACK_COLORS[t] || '#64748b']));

    // 매번 destroy 후 다시 generate하는 방식으로 안전하게 처리 (기존 바 차트에서도 같은 이유로 사용).
    if (chartInstanceRef.current) {
      try {
        chartInstanceRef.current.destroy();
      } catch (e) {
        // destroy 중 에러가 나도 무시하고 새로 생성
      }
      chartInstanceRef.current = null;
    }

    try {
      chartInstanceRef.current = bb.generate({
        bindto: chartContainerRef.current,
        size: { height: 200 },
        data: {
          x: 'x',
          columns: [xColumn, ...typeColumns],
          type: spline(),
          names: TYPE_LABELS,
          colors,
        },
        point: { r: 2 },
        axis: {
          x: {
            type: 'timeseries',
            tick: { format: '%H:%M:%S', text: { style: { fill: '#94a3b8' } } },
          },
          y: {
            tick: { format: (v) => Math.round(v), text: { style: { fill: '#94a3b8' } } },
            min: 0,
            padding: { bottom: 0 },
          },
        },
        legend: { show: true, position: 'bottom' },
        grid: { y: { show: false } },
        tooltip: {
          format: {
            title: (x) => new Date(x).toLocaleTimeString(),
            value: (value) => `${value}건`,
          },
        },
      });
    } catch (e) {
      console.error('차트 생성 실패:', e);
    }
  }, [timeline, page]);

  // 공격 유형 비율 도넛 (추이 차트와 같은 최근 5분 데이터 기준)
  useEffect(() => {
    if (!donutContainerRef.current) return;

    const totals = {};
    for (const b of timeline) {
      for (const [t, n] of Object.entries(b.counts)) totals[t] = (totals[t] || 0) + n;
    }
    const types = Object.keys(totals);
    const sum = types.reduce((s, t) => s + totals[t], 0);
    const columns = types.map(t => [t, totals[t]]);
    const colors = Object.fromEntries(types.map(t => [t, ATTACK_COLORS[t] || '#64748b']));

    // 같은 자리에 이미 그려진 차트는 데이터만 교체: 매번 destroy/generate 하면
    // 그리기 애니메이션 도중 파괴되어 'innerRadius of null' 런타임 오류가 남
    const inst = donutInstanceRef.current;
    if (inst && donutBoundElRef.current === donutContainerRef.current) {
      inst.data.colors(colors);
      inst.load({ columns, unload: true });
      return;
    }
    if (inst) {
      try { inst.destroy(); } catch (e) { /* 무시 */ }
      donutInstanceRef.current = null;
    }
    if (sum === 0) return;

    try {
      donutInstanceRef.current = bb.generate({
        bindto: donutContainerRef.current,
        size: { height: page === 'overview' ? 320 : 200 },
        data: { columns, type: donut(), colors, names: TYPE_LABELS },
        donut: { width: 28, label: { show: false } },
        legend: { show: true, position: 'right' },
        tooltip: { format: { value: (v, ratio) => `${v}건 (${(ratio * 100).toFixed(0)}%)` } },
        transition: { duration: 0 },
      });
      donutBoundElRef.current = donutContainerRef.current;
    } catch (e) {
      console.error('도넛 차트 생성 실패:', e);
    }
  }, [timeline, page]);

  useEffect(() => {
    return () => {
      if (chartInstanceRef.current) {
        chartInstanceRef.current.destroy();
        chartInstanceRef.current = null;
      }
      if (donutInstanceRef.current) {
        donutInstanceRef.current.destroy();
        donutInstanceRef.current = null;
      }
    };
  }, []);

  // 첫 로드로 받은 로그가 그려진 뒤부터 새로 들어오는 행만 하이라이트
  useEffect(() => {
    if (connected) logsSeededRef.current = true;
  }, [logs, connected]);

  const enableNotifications = () => {
    Notification.requestPermission().then(perm => {
      if (perm === 'granted') alert('알림이 활성화됐습니다!');
      else alert('알림 권한이 거부됐습니다. 사파리 설정에서 허용해주세요.');
    });
  };

  useEffect(() => {
    fetchData();
    fetchWatchlist();
    fetchBlockedIps();
    const interval = setInterval(() => { fetchData(); fetchWatchlist(); fetchBlockedIps(); }, 5000);

    let ws;
    let reconnectTimer;
    let cleanedUp = false;

    const connect = () => {
      if (cleanedUp) return;
      ws = new WebSocket('ws://localhost:8000/ws');
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!cleanedUp) reconnectTimer = setTimeout(connect, 3000);
      };
      ws.onmessage = (event) => {
        const newLog = JSON.parse(event.data);
        if (newLog.type === 'server_log') {
          setServerLogs(prev => [newLog, ...prev].slice(0, 100));
          return;
        }
        if (newLog.type === 'blocked_ip_update') {
          fetchBlockedIps();
          return;
        }
        if (newLog.is_attack === true || newLog.is_attack === 1) {
          addTimelineEvent(newLog.attack_type, parseTimestamp(newLog.timestamp));
          if (newLog.confidence >= LEVEL_CRITICAL) setUnacked(n => n + 1);
          if (newLog.attack_type === 'Honeypot') {
            fetchWatchlist();
          }
          if (newLog.blocked && Notification.permission === 'granted') {
            new Notification('🚫 IP 차단됨 — 관리자 검토 필요', {
              body: `${typeLabel(newLog.attack_type)} | IP: ${newLog.attacker_ip} | 블랙리스트 등록됨, 검토 후 조치하세요.`,
              icon: '/favicon.ico'
            });
            fetchBlockedIps();
          } else if (newLog.confidence >= LEVEL_CRITICAL && Notification.permission === 'granted') {
            new Notification('🔴 Critical 공격 탐지!', {
              body: `${typeLabel(newLog.attack_type)} | IP: ${newLog.attacker_ip}`,
              icon: '/favicon.ico'
            });
          }
        }
        setLogs(prev => [newLog, ...prev].slice(0, 50));
        setStats(prev => ({
          ...prev,
          total: prev.total + 1,
          attack: newLog.is_attack ? prev.attack + 1 : prev.attack,
          benign: !newLog.is_attack ? prev.benign + 1 : prev.benign,
        }));
      };
    };

    connect();

    return () => {
      cleanedUp = true;
      clearInterval(interval);
      clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, []);

  // 위협 피드 행: 안정적인 key를 만들고, 처음 나타난 지 얼마 안 된 행은 하이라이트
  const now = Date.now();
  const seenKeys = {};
  const feedRows = logs.map((log) => {
    const base = `${log.timestamp}|${log.attacker_ip}|${log.attack_type}`;
    seenKeys[base] = (seenKeys[base] || 0) + 1;
    const key = `${base}|${seenKeys[base]}`;
    if (!rowArrivedRef.current.has(key)) rowArrivedRef.current.set(key, logsSeededRef.current ? now : 0);
    return { log, key, isNew: now - rowArrivedRef.current.get(key) < ROW_HIGHLIGHT_MS };
  });
  if (rowArrivedRef.current.size > 500) {
    const live = new Set(feedRows.map(r => r.key));
    for (const k of rowArrivedRef.current.keys()) if (!live.has(k)) rowArrivedRef.current.delete(k);
  }

  const hasAttacks = timeline.some(b => Object.keys(b.counts).length > 0);
  const recentAttackTotal = timeline.reduce((s, b) => s + Object.values(b.counts).reduce((a, n) => a + n, 0), 0);
  const attackRatio = stats.total > 0 ? ((stats.attack / stats.total) * 100).toFixed(1) : null;
  const pendingReview = blockedIps.filter(b => !b.reviewed && !b.permanent).length;

  const emptyChart = (Icon, text) => (
    <div style={{
      position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center', color: '#475569', gap: '8px', zIndex: 1,
    }}>
      <Icon size={32} color="#334155" />
      <span style={{ fontSize: '14px' }}>{text}</span>
    </div>
  );

  const importanceBars = (features, color) => {
    const max = features[0][1];
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {features.map(([label, v]) => (
          <div key={label} style={{ display: 'grid', gridTemplateColumns: '170px 1fr 52px', alignItems: 'center', gap: '10px', fontSize: '13px' }}>
            <span style={{ color: '#cbd5e1' }}>{label}</span>
            <div style={{ height: '8px', background: '#334155', borderRadius: '4px', overflow: 'hidden' }}>
              <div style={{ width: `${(v / max) * 100}%`, height: '100%', background: color }} />
            </div>
            <span style={{ color: '#94a3b8', textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>{(v * 100).toFixed(1)}%</span>
          </div>
        ))}
      </div>
    );
  };

  const feedTable = (rows) => (
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>탐지 시간</th>
                  <th style={styles.th}>공격 유형</th>
                  <th style={styles.th}>공격자 IP</th>
                  <th style={styles.th}>모델 신뢰도</th>
                  <th style={styles.th}>방어 상태</th>
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ ...styles.td, textAlign: 'center', padding: '48px', color: '#475569' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
                        <ShieldAlert size={36} color="#334155" />
                        <span style={{ fontSize: '15px' }}>탐지된 위협 없음</span>
                        <span style={{ fontSize: '12px', color: '#334155' }}>IPS가 실행되면 탐지 로그가 여기에 표시됩니다</span>
                      </div>
                    </td>
                  </tr>
                ) : rows.map(({ log, key, isNew }) => {
                  const level = LEVELS[threatLevel(log)];
                  const pct = Math.round((log.confidence || 0) * 100);
                  return (
                    <tr key={key} className={isNew ? 'row-new clickable' : 'clickable'} onClick={() => setSelected(log)} title="클릭하면 상세 정보">
                      <td style={{ ...styles.td, color: '#94a3b8', fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>{log.timestamp}</td>
                      <td style={styles.td}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', fontWeight: 'bold', color: log.is_attack ? '#f1f5f9' : log.attack_type === 'Suspicious' ? level.color : '#22c55e' }}>
                          <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: log.is_attack ? (ATTACK_COLORS[log.attack_type] || '#64748b') : log.attack_type === 'Suspicious' ? level.color : '#22c55e' }} />
                          {typeLabel(log.attack_type)}
                        </span>
                      </td>
                      <td style={{ ...styles.td, fontFamily: 'monospace' }}>{log.attacker_ip}</td>
                      <td style={styles.td}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '150px' }}>
                          <div style={{ flex: 1, height: '6px', borderRadius: '3px', backgroundColor: '#334155', overflow: 'hidden' }}>
                            <div style={{ width: `${pct}%`, height: '100%', backgroundColor: level.color }} />
                          </div>
                          <span style={{ fontSize: '12px', color: level.color, fontWeight: 'bold', width: '84px', fontVariantNumeric: 'tabular-nums' }}>
                            {pct}% {level.label}
                          </span>
                        </div>
                      </td>
                      <td style={styles.td}><span style={styles.badge(log.blocked)}>{log.blocked ? '차단 완료' : '탐지됨'}</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
  );

  const donutCard = (
        <div style={styles.card}>
          <div style={{ ...styles.cardTitle, marginBottom: '12px' }}><PieChart size={18} /> 공격 유형 비율 (최근 5분){hasAttacks && <span style={{ marginLeft: 'auto', color: '#f1f5f9' }}>{recentAttackTotal}건</span>}</div>
          <div style={{ position: 'relative', width: '100%' }}>
            {!hasAttacks && emptyChart(PieChart, '데이터 없음')}
            <div ref={donutContainerRef} style={{ width: '100%', height: page === 'overview' ? '320px' : '200px', visibility: hasAttacks ? 'visible' : 'hidden' }} />
          </div>
        </div>
  );

  const adviceTypes = Object.entries(typeCounts).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
  const counts = { events: stats.attack, advice: adviceTypes.length, blocked: blockedIps.length, watchlist: watchlist.length, server: serverLogs.length };
  const pageInfo = PAGES.find(pg => pg.id === page);

  return (
    <div style={styles.container}>
      {unacked > 0 && <div className="critical-alarm" />}

      <header style={styles.header}>
        <h1 style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: 0, fontSize: '26px', flexWrap: 'wrap' }}>
          <ShieldAlert size={32} color="#3b82f6" /> ML 기반 실시간 침입 방지 시스템
          {ipsRunning ? (
            <span style={styles.pill('#14532d', '#86efac')}><span className="pulse-dot" /> 실시간 보호 중</span>
          ) : (
            <span style={styles.pill('#334155', '#94a3b8')}>■ 중지됨</span>
          )}
          <span style={connected ? styles.pill('#1e3a5f', '#93c5fd') : styles.pill('#7f1d1d', '#fca5a5')}>
            {connected ? '● 백엔드 연결됨' : '● 연결 끊김'}
          </span>
        </h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {ipsRunning ? (
            <button onClick={handleStop} style={styles.headerBtn('#ef4444')}>■ 중지</button>
          ) : (
            <button onClick={handleStart} style={styles.headerBtn('#22c55e')}>▶ 시작</button>
          )}
          {unacked > 0 && (
            <button onClick={() => setUnacked(0)} className="alarm-ack" style={styles.headerBtn('#be123c')}>⚠ 미확인 경고 {unacked}건 · 확인</button>
          )}
          <button onClick={handleEmergencyReset} style={styles.headerBtn('#f59e0b')}>🚨 긴급 해제</button>
          <button onClick={enableNotifications} style={{ ...styles.headerBtn('#334155', '#94a3b8'), fontWeight: 'normal', fontSize: '13px' }}>🔔 알림 허용</button>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#94a3b8', fontVariantNumeric: 'tabular-nums' }}>
            <Clock size={18} /> {currentTime}
          </div>
        </div>
      </header>

      <div className="app-shell">
        {/* 사이드바 메뉴 */}
        <nav className="sidebar">
          {PAGES.map(({ id, label, icon: Icon }) => (
            <a key={id} href={`#/${id}`} className={page === id ? 'nav-item active' : 'nav-item'}>
              <Icon size={18} />
              <span style={{ flex: 1 }}>{label}</span>
              {counts[id] > 0 && <span className="nav-count">{counts[id]}</span>}
            </a>
          ))}
        </nav>

        <main style={{ minWidth: 0 }}>
          <h2 style={{ fontSize: '22px', margin: '0 0 16px', color: '#f1f5f9' }}>{pageInfo.label}</h2>

          {page === 'overview' && (<>
      {/* KPI */}
      <div className="kpi-row">
        <div style={styles.card}>
          <div style={styles.cardTitle}><Activity size={18} /> 전체 탐지</div>
          <div style={styles.kpiValue('#f1f5f9')}>{stats.total.toLocaleString()} <span style={{ fontSize: '16px' }}>건</span></div>
          <div style={styles.kpiSub}>정상 {stats.benign.toLocaleString()}건</div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}><ShieldAlert size={18} /> 공격 탐지</div>
          <div style={styles.kpiValue('#ef4444')}>{stats.attack.toLocaleString()} <span style={{ fontSize: '16px' }}>건</span></div>
          <div style={styles.kpiSub}>{attackRatio !== null ? `전체 트래픽의 ${attackRatio}%` : '—'}</div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}><Ban size={18} /> 차단 IP</div>
          <div style={styles.kpiValue('#f43f5e')}>{blockedIps.length} <span style={{ fontSize: '16px' }}>IP</span></div>
          <div style={styles.kpiSub}>{pendingReview > 0 ? `관리자 검토 대기 ${pendingReview}건` : '검토 대기 없음'}</div>
        </div>
        <div style={styles.card}>
          <div style={styles.cardTitle}><Eye size={18} /> 감시목록</div>
          <div style={styles.kpiValue('#06b6d4')}>{watchlist.length} <span style={{ fontSize: '16px' }}>IP</span></div>
          <div style={styles.kpiSub}>허니팟·반복 공격 자동 등록</div>
        </div>
      </div>
          <div className="dash-row">
            <section style={styles.panel}>
              <div style={styles.panelHeader}>
                <span>📍 최근 탐지 10건</span>
                <button onClick={() => go('events')} style={{ background: 'none', border: 'none', color: '#93c5fd', cursor: 'pointer', fontSize: '13px' }}>탐지 로그 전체 보기 →</button>
              </div>
              {feedTable(feedRows.slice(0, 10))}
            </section>
            {donutCard}
          </div>
          </>)}

          {page === 'events' && (<>
          <div className="dash-row">
        <div style={styles.card}>
          <div style={{ ...styles.cardTitle, marginBottom: '12px' }}><BarChart3 size={18} /> 공격 유형별 탐지 추이 (최근 5분)</div>
          <div style={{ position: 'relative', width: '100%' }}>
            {!hasAttacks && emptyChart(BarChart3, '탐지된 공격 없음')}
            <div ref={chartContainerRef} style={{ width: '100%', height: '200px', visibility: hasAttacks ? 'visible' : 'hidden' }} />
          </div>
        </div>
            {donutCard}
          </div>
          <section style={styles.panel}>
            <div style={styles.panelHeader}>
              <span>📍 실시간 위협 피드</span>
              <span style={styles.panelHint}>최근 50건 · ML 모델 판정</span>
            </div>
            <div className="scroll-y" style={{ maxHeight: 'calc(100vh - 560px)', minHeight: '300px' }}>
              {feedTable(feedRows)}
            </div>
          </section>
          </>)}

          {page === 'advice' && (adviceTypes.length === 0 ? (
            <section style={styles.panel}><div style={styles.empty}>탐지된 공격이 없어 권고사항이 없습니다</div></section>
          ) : (<>
            <p style={{ color: '#94a3b8', margin: '0 0 16px', fontSize: '14px' }}>ML 탐지 결과를 바탕으로 공격 유형별 권고 조치를 자동으로 정리합니다 · 탐지가 많은 순</p>
            <div className="advice-grid">
              {adviceTypes.map(([type, n], i) => {
                const a = ADVICE[type] || ADVICE_DEFAULT;
                const blockedN = blockedIps.filter(b => b.attack_type === type).length;
                return (
                  <section key={type} style={{ ...styles.panel, padding: '20px 24px', gap: '12px', borderTop: `3px solid ${ATTACK_COLORS[type] || '#64748b'}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '20px', fontWeight: 'bold' }}>{typeLabel(type)}</span>
                      <span style={{ color: '#f1f5f9', fontVariantNumeric: 'tabular-nums' }}>{n}건</span>
                      <span style={styles.threatBadge(a.risk)}>{a.risk === 'high' ? '위험도 높음' : '위험도 중간'}</span>
                      {i === 0 && <span style={styles.countBadge('#f59e0b')}>우선 대응</span>}
                    </div>
                    <p style={{ margin: 0, color: '#94a3b8', fontSize: '14px' }}>{a.desc}</p>
                    <ul style={{ margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '14px', lineHeight: 1.5 }}>
                      {a.actions.map(act => <li key={act}>{act}</li>)}
                    </ul>
                    <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>자동 대응 현황: 차단 {blockedN} IP</p>
                  </section>
                );
              })}
            </div>
          </>))}

          {page === 'model' && (<>
            <p style={{ color: '#94a3b8', margin: '0 0 16px', fontSize: '14px' }}>두 모델 모두 Random Forest입니다. 판정 확률(신뢰도)이 그대로 4단계 자동 대응의 기준이 됩니다.</p>
            <div className="model-grid">
              {['flow', 'http'].map(id => {
                const m = MODELS[id];
                return (
                  <section key={id} style={{ ...styles.panel, padding: '20px 24px', gap: '16px' }}>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: '10px', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '20px', fontWeight: 'bold' }}>{m.name}</span>
                      <span style={styles.panelHint}>{m.algo}</span>
                    </div>
                    <div style={{ fontSize: '14px', color: '#94a3b8', lineHeight: 1.7 }}>입력: {m.input}<br />학습 데이터: {m.data}</div>
                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                      {m.classes.map(c => <span key={c} style={{ padding: '3px 10px', borderRadius: '12px', fontSize: '12px', background: '#334155', color: '#e2e8f0' }}>{c}</span>)}
                    </div>
                    <div className="metric-row" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
                      {m.metrics.map(([k, v]) => (
                        <div key={k} style={{ background: '#0f172a', borderRadius: '10px', padding: '12px 14px' }}>
                          <div style={{ fontSize: '22px', fontWeight: 'bold', fontVariantNumeric: 'tabular-nums' }}>{v}</div>
                          <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '2px' }}>{k}</div>
                        </div>
                      ))}
                    </div>
                    <div>
                      <div style={{ fontSize: '14px', fontWeight: 'bold', marginBottom: '10px' }}>판정에 중요한 특징 TOP 10</div>
                      {importanceBars(m.features, id === 'flow' ? '#a855f7' : '#3b82f6')}
                    </div>
                  </section>
                );
              })}
            </div>

            <div className="model-grid" style={{ marginTop: '20px' }}>
              <section style={styles.panel}>
                <div style={styles.panelHeader}><span>흐름 모델 · 학습 데이터별 정확도</span><span style={styles.panelHint}>같은 평가 데이터로 비교</span></div>
                <table style={styles.table}>
                  <thead><tr><th style={styles.th}>학습 데이터</th><th style={{ ...styles.th, textAlign: 'right' }}>시연 환경 평가</th><th style={{ ...styles.th, textAlign: 'right' }}>공개 데이터 평가</th></tr></thead>
                  <tbody>
                    {FLOW_COMPARISON.map(([name, own, pub], i) => {
                      const chosen = i === FLOW_COMPARISON.length - 1;
                      return (
                        <tr key={name} style={chosen ? { background: '#1e3a5f' } : undefined}>
                          <td style={{ ...styles.td, fontWeight: chosen ? 'bold' : 'normal' }}>{name}</td>
                          <td style={{ ...styles.td, textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>{own}</td>
                          <td style={{ ...styles.td, textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>{pub}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                <p style={{ margin: 0, padding: '14px 20px', fontSize: '13px', color: '#94a3b8' }}>공개 데이터만으로는 실제 환경에서 24%로 떨어져, 직접 캡처 데이터를 합친 하이브리드를 채택했습니다.</p>
              </section>

              <section style={styles.panel}>
                <div style={styles.panelHeader}><span>혼동 행렬 · 하이브리드 흐름 모델</span><span style={styles.panelHint}>직접 캡처 평가 70,776건 · 행: 실제, 열: 예측</span></div>
                <table style={styles.table}>
                  <thead><tr><th style={styles.th}>실제 \ 예측</th>{CONFUSION.classes.map(c => <th key={c} style={{ ...styles.th, textAlign: 'right' }}>{c}</th>)}</tr></thead>
                  <tbody>
                    {CONFUSION.matrix.map((row, r) => (
                      <tr key={r}>
                        <td style={{ ...styles.td, color: '#94a3b8' }}>{CONFUSION.classes[r]}</td>
                        {row.map((n, c) => (
                          <td key={c} style={{ ...styles.td, textAlign: 'right', fontVariantNumeric: 'tabular-nums', fontWeight: r === c ? 'bold' : 'normal', color: r === c ? '#86efac' : n > 0 ? '#fca5a5' : '#475569' }}>{n.toLocaleString()}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p style={{ margin: 0, padding: '14px 20px', fontSize: '13px', color: '#94a3b8' }}>공격 유형끼리 헷갈린 경우는 0건이고, 정상 ↔ BruteForce 혼동만 0.1~0.4% 있습니다.</p>
              </section>
            </div>

            <section style={{ ...styles.panel, marginTop: '20px' }}>
              <div style={styles.panelHeader}><span>신뢰도에 따른 자동 대응</span><span style={styles.panelHint}>흐름 모델 신뢰도 80% 미만은 차단 없이 '미분류 의심'으로 표시</span></div>
              <div className="metric-row" style={{ padding: '16px 20px' }}>
                {RESPONSE_LEVELS.map(([lv, th, act]) => (
                  <div key={lv} style={{ background: lv === 'CRITICAL' ? '#7f1d1d' : '#0f172a', borderRadius: '10px', padding: '14px 16px' }}>
                    <div style={{ fontSize: '12px', color: '#94a3b8' }}>{th}</div>
                    <div style={{ fontSize: '18px', fontWeight: 'bold', margin: '4px 0' }}>{lv}</div>
                    <div style={{ fontSize: '13px', color: '#cbd5e1' }}>{act}</div>
                  </div>
                ))}
              </div>
            </section>
          </>)}

          {page === 'blocked' && (
          <section style={styles.panel}>
            <div style={styles.panelHeader}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                🚫 차단 관리 {blockedIps.length > 0 && <span style={styles.countBadge('#ef4444')}>{blockedIps.length}</span>}
              </span>
              <span style={styles.panelHint}>기본 10분 후 자동 해제</span>
            </div>
            <div className="scroll-y" style={{ maxHeight: 'calc(100vh - 260px)' }}>
              {blockedIps.length === 0 ? (
                <div style={styles.empty}>현재 차단된 IP 없음</div>
              ) : blockedIps.map((item) => (
                <div key={item.id} style={styles.listItem}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontFamily: 'monospace', color: '#ef4444', fontWeight: 'bold' }}>{item.ip}</span>
                    {item.permanent
                      ? <span style={styles.threatBadge('critical')}>영구 차단</span>
                      : item.reviewed
                        ? <span style={styles.threatBadge('medium')}>검토 완료(10분)</span>
                        : <span style={styles.threatBadge('high')}>검토 대기</span>}
                  </div>
                  <div style={{ fontSize: '12px', color: '#94a3b8', margin: '6px 0 8px' }}>
                    {typeLabel(item.attack_type)} · {item.blocked_at}{!item.permanent && ` → ${item.auto_unblock_at} 해제`}
                  </div>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    <button onClick={() => handleBlockedDecision(item.ip, 'keep_10min')} style={styles.smallBtn('#fcd34d')}>10분 유지</button>
                    <button onClick={() => handleBlockedDecision(item.ip, 'permanent')} style={styles.smallBtn('#f9a8d4')}>영구 차단</button>
                    <button onClick={() => handleBlockedDecision(item.ip, 'unblock')} style={styles.smallBtn('#86efac')}>즉시 해제</button>
                  </div>
                </div>
              ))}
            </div>
          </section>
          )}

          {page === 'watchlist' && (
          <section style={styles.panel}>
            <div style={styles.panelHeader}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                👁 감시목록 {watchlist.length > 0 && <span style={styles.countBadge('#06b6d4')}>{watchlist.length}</span>}
              </span>
              <span style={styles.panelHint}>신뢰도 +20% 가중 적용</span>
            </div>
            <div className="scroll-y" style={{ maxHeight: 'calc(100vh - 260px)' }}>
              {watchlist.length === 0 ? (
                <div style={styles.empty}>감시 중인 IP 없음</div>
              ) : watchlist.map((item) => (
                <div key={item.id} style={{ ...styles.listItem, display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontFamily: 'monospace', color: '#06b6d4', fontWeight: 'bold' }}>{item.ip}</span>
                      <span style={styles.threatBadge(item.threat_level)}>{item.threat_level.toUpperCase()}</span>
                    </div>
                    <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {item.reason} · {item.added_at}
                    </div>
                  </div>
                  <button
                    onClick={() => handleRemoveWatchlist(item.ip)}
                    title="감시목록에서 제거"
                    style={{ background: 'none', border: '1px solid #475569', borderRadius: '6px', padding: '4px 8px', cursor: 'pointer', color: '#ef4444' }}
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              ))}
            </div>
          </section>
          )}

          {page === 'server' && (<>
      {/* 서버 접속 로그 */}
      <section style={styles.panel}>
        <div
          style={{ ...styles.panelHeader, cursor: 'pointer', borderBottom: serverLogsOpen ? styles.panelHeader.borderBottom : 'none' }}
          onClick={() => setServerLogsOpen(o => !o)}
        >
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={16} /> 서버 접속 로그 (실제 서버 / 허니팟)
            {serverLogs.length > 0 && <span style={styles.countBadge('#475569')}>{serverLogs.length}</span>}
          </span>
          {serverLogsOpen ? <ChevronUp size={18} color="#94a3b8" /> : <ChevronDown size={18} color="#94a3b8" />}
        </div>
        {serverLogsOpen && (
          <div className="scroll-y" style={{ maxHeight: 'calc(100vh - 300px)' }}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>서버</th>
                  <th style={styles.th}>IP</th>
                  <th style={styles.th}>메서드</th>
                  <th style={styles.th}>경로</th>
                  <th style={styles.th}>페이로드</th>
                  <th style={styles.th}>시각</th>
                </tr>
              </thead>
              <tbody>
                {serverLogs.length === 0 ? (
                  <tr><td colSpan={6} style={{ ...styles.td, textAlign: 'center', color: '#475569' }}>접속 기록 없음</td></tr>
                ) : serverLogs.map((log, i) => (
                  <tr key={i}>
                    <td style={styles.td}>
                      <span style={{ padding: '3px 8px', borderRadius: '12px', fontSize: '12px', fontWeight: 'bold',
                        backgroundColor: log.server_type === 'honeypot' ? '#164e63' : '#14532d',
                        color: log.server_type === 'honeypot' ? '#67e8f9' : '#86efac' }}>
                        {log.server_type === 'honeypot' ? '🍯 허니팟' : '🌐 실제'}
                      </span>
                    </td>
                    <td style={{ ...styles.td, fontFamily: 'monospace', color: '#f97316' }}>{log.ip}</td>
                    <td style={styles.td}>{log.method}</td>
                    <td style={{ ...styles.td, fontFamily: 'monospace', color: '#94a3b8' }}>{log.path}</td>
                    <td style={{ ...styles.td, color: log.payload ? '#eab308' : '#475569', maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {log.payload || '-'}
                    </td>
                    <td style={{ ...styles.td, whiteSpace: 'nowrap' }}>{log.timestamp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
          </>)}
        </main>
      </div>
      {selected && (() => {
        const log = selected;
        const level = LEVELS[threatLevel(log)];
        const pct = Math.round((log.confidence || 0) * 100);
        const suspicious = log.attack_type === 'Suspicious';
        const m = MODELS[modelOf(log.attack_type)];
        const advice = log.is_attack ? (ADVICE[log.attack_type] || ADVICE_DEFAULT) : null;
        const label = typeLabel(log.attack_type);
        return (
          <div className="modal-backdrop" onClick={() => setSelected(null)}>
            <div className="modal" onClick={e => e.stopPropagation()} role="dialog" aria-label={`${label} 상세 정보`}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                <span style={{ width: '12px', height: '12px', borderRadius: '50%', background: log.is_attack ? (ATTACK_COLORS[log.attack_type] || '#64748b') : suspicious ? level.color : '#22c55e' }} />
                <span style={{ fontSize: '22px', fontWeight: 'bold' }}>{label}</span>
                <span style={{ ...styles.pill('#0f172a', level.color), fontWeight: 'bold' }}>{level.label}</span>
                <button onClick={() => setSelected(null)} aria-label="닫기" style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}><X size={22} /></button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '20px', fontSize: '14px' }}>
                {[['탐지 시간', log.timestamp], ['공격자 IP', log.attacker_ip], ['방어 상태', log.blocked ? '차단 완료' : log.is_attack ? '탐지됨 (단계별 대응 중)' : '조치 없음'], ['판정 모델', `${m.name} · ${m.algo}`]].map(([k, v]) => (
                  <div key={k} style={{ background: '#0f172a', borderRadius: '10px', padding: '10px 14px' }}>
                    <div style={{ fontSize: '12px', color: '#94a3b8' }}>{k}</div>
                    <div style={{ marginTop: '2px', fontFamily: k === '공격자 IP' ? 'monospace' : 'inherit' }}>{v}</div>
                  </div>
                ))}
              </div>

              <div style={{ fontSize: '15px', fontWeight: 'bold', marginBottom: '8px' }}>🧠 ML 판단</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                <div style={{ flex: 1, height: '10px', borderRadius: '5px', background: '#334155', overflow: 'hidden' }}>
                  <div style={{ width: `${pct}%`, height: '100%', background: level.color }} />
                </div>
                <span style={{ color: level.color, fontWeight: 'bold', fontVariantNumeric: 'tabular-nums' }}>신뢰도 {pct}%</span>
              </div>
              <p style={{ margin: '0 0 12px', fontSize: '13px', color: '#94a3b8' }}>
                {suspicious ? '모델 신뢰도가 80% 미만이라 차단하지 않고 미분류로 표시했습니다. 학습하지 않은 유형의 공격일 수 있습니다.'
                  : `${m.name}이 ${m.input}을 보고 판정했습니다. 이 모델이 판정에 가장 많이 쓰는 특징:`}
              </p>
              {!suspicious && importanceBars(m.features.slice(0, 5), modelOf(log.attack_type) === 'flow' ? '#a855f7' : '#3b82f6')}

              {advice && (<>
                <div style={{ fontSize: '15px', fontWeight: 'bold', margin: '20px 0 8px' }}>🛡 대응 방법</div>
                <p style={{ margin: '0 0 8px', fontSize: '13px', color: '#94a3b8' }}>{advice.desc}</p>
                <ol style={{ margin: 0, paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '14px', lineHeight: 1.5 }}>
                  {advice.actions.map(a => <li key={a}>{a}</li>)}
                </ol>
                <a href={`https://www.google.com/search?q=${encodeURIComponent(`${typeLabel(log.attack_type)} 공격 대응 방법`)}`} target="_blank" rel="noopener noreferrer"
                  style={{ display: 'inline-block', marginTop: '16px', padding: '8px 16px', borderRadius: '8px', background: '#3b82f6', color: '#fff', textDecoration: 'none', fontSize: '14px', fontWeight: 'bold' }}>
                  🔎 {typeLabel(log.attack_type)} 대응 방법 더 찾아보기
                </a>
              </>)}
              {!log.is_attack && !suspicious && <p style={{ marginTop: '20px', fontSize: '14px', color: '#86efac' }}>정상 트래픽으로 판정되어 조치가 필요 없습니다.</p>}
            </div>
          </div>
        );
      })()}
    </div>
  );
}

export default App;
