import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { ShieldAlert, Activity, BarChart3, Clock, Eye, Trash2, Ban, PieChart, Server, ChevronDown, ChevronUp } from 'lucide-react';
import bb, { spline, donut } from 'billboard.js';
import 'billboard.js/dist/billboard.css';
import './App.css';

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
  const [flashKey, setFlashKey] = useState(0); // Critical 탐지 때마다 증가 -> 경고 오버레이 재생
  const [logs, setLogs] = useState([]);
  const [serverLogs, setServerLogs] = useState([]);
  const [stats, setStats] = useState({ total: 0, benign: 0, attack: 0, status: "연결 대기 중..." });
  const [currentTime, setCurrentTime] = useState(new Date().toLocaleTimeString());
  const [connected, setConnected] = useState(false);
  const [ipsRunning, setIpsRunning] = useState(false);
  const [timeline, setTimeline] = useState([]); // [{ t: epochMs, counts: { SQLi: n, ... } }] - 창 전체를 빈틈없이 채운 배열
  const [watchlist, setWatchlist] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);
  const chartContainerRef = useRef(null);
  const chartInstanceRef = useRef(null);
  const donutContainerRef = useRef(null);
  const donutInstanceRef = useRef(null);
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
      const [logRes, statRes, statusRes, serverLogRes] = await Promise.all([
        axios.get('http://localhost:8000/logs'),
        axios.get('http://localhost:8000/stats'),
        axios.get('http://localhost:8000/ips_status'),
        axios.get('http://localhost:8000/server_logs'),
      ]);
      setLogs(logRes.data);
      setStats(statRes.data);
      setIpsRunning(statusRes.data.running);
      setServerLogs(serverLogRes.data.reverse());
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
  }, [timeline]);

  // 공격 유형 비율 도넛 (추이 차트와 같은 최근 5분 데이터 기준)
  useEffect(() => {
    if (!donutContainerRef.current) return;

    const totals = {};
    for (const b of timeline) {
      for (const [t, n] of Object.entries(b.counts)) totals[t] = (totals[t] || 0) + n;
    }
    const types = Object.keys(totals);
    const sum = types.reduce((s, t) => s + totals[t], 0);

    if (donutInstanceRef.current) {
      try { donutInstanceRef.current.destroy(); } catch (e) { /* 무시 */ }
      donutInstanceRef.current = null;
    }
    if (sum === 0) return;

    try {
      donutInstanceRef.current = bb.generate({
        bindto: donutContainerRef.current,
        size: { height: 200 },
        data: {
          columns: types.map(t => [t, totals[t]]),
          type: donut(),
          colors: Object.fromEntries(types.map(t => [t, ATTACK_COLORS[t] || '#64748b'])),
        },
        donut: { title: `${sum}건`, width: 28, label: { show: false } },
        legend: { show: true, position: 'right' },
        tooltip: { format: { value: (v, ratio) => `${v}건 (${(ratio * 100).toFixed(0)}%)` } },
        transition: { duration: 0 },
      });
    } catch (e) {
      console.error('도넛 차트 생성 실패:', e);
    }
  }, [timeline]);

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
          if (newLog.confidence >= LEVEL_CRITICAL) setFlashKey(k => k + 1);
          if (newLog.attack_type === 'Honeypot') {
            fetchWatchlist();
          }
          if (newLog.blocked && Notification.permission === 'granted') {
            new Notification('🚫 IP 차단됨 — 관리자 검토 필요', {
              body: `${newLog.attack_type} | IP: ${newLog.attacker_ip} | 블랙리스트 등록됨, 검토 후 조치하세요.`,
              icon: '/favicon.ico'
            });
            fetchBlockedIps();
          } else if (newLog.confidence >= LEVEL_CRITICAL && Notification.permission === 'granted') {
            new Notification('🔴 Critical 공격 탐지!', {
              body: `${newLog.attack_type} | IP: ${newLog.attacker_ip}`,
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

  return (
    <div style={styles.container}>
      {flashKey > 0 && <div key={flashKey} className="critical-flash" />}

      <header style={styles.header}>
        <h1 style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: 0, fontSize: '26px', flexWrap: 'wrap' }}>
          <ShieldAlert size={32} color="#3b82f6" /> AI 기반 차세대 실시간 IPS
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
          <button onClick={handleEmergencyReset} style={styles.headerBtn('#f59e0b')}>🚨 긴급 해제</button>
          <button onClick={enableNotifications} style={{ ...styles.headerBtn('#334155', '#94a3b8'), fontWeight: 'normal', fontSize: '13px' }}>🔔 알림 허용</button>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#94a3b8', fontVariantNumeric: 'tabular-nums' }}>
            <Clock size={18} /> {currentTime}
          </div>
        </div>
      </header>

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

      {/* 차트 */}
      <div className="dash-row">
        <div style={styles.card}>
          <div style={{ ...styles.cardTitle, marginBottom: '12px' }}><BarChart3 size={18} /> 공격 유형별 탐지 추이 (최근 5분)</div>
          <div style={{ position: 'relative', width: '100%' }}>
            {!hasAttacks && emptyChart(BarChart3, '탐지된 공격 없음')}
            <div ref={chartContainerRef} style={{ width: '100%', height: '200px', visibility: hasAttacks ? 'visible' : 'hidden' }} />
          </div>
        </div>
        <div style={styles.card}>
          <div style={{ ...styles.cardTitle, marginBottom: '12px' }}><PieChart size={18} /> 공격 유형 비율 (최근 5분)</div>
          <div style={{ position: 'relative', width: '100%' }}>
            {!hasAttacks && emptyChart(PieChart, '데이터 없음')}
            <div ref={donutContainerRef} style={{ width: '100%', height: '200px', visibility: hasAttacks ? 'visible' : 'hidden' }} />
          </div>
        </div>
      </div>

      {/* 위협 피드 + 차단/감시 */}
      <div className="dash-row">
        <section style={styles.panel}>
          <div style={styles.panelHeader}>
            <span>📍 실시간 위협 피드</span>
            <span style={styles.panelHint}>최근 50건 · ML 모델 판정</span>
          </div>
          <div className="scroll-y" style={{ maxHeight: '460px' }}>
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
                {feedRows.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ ...styles.td, textAlign: 'center', padding: '48px', color: '#475569' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
                        <ShieldAlert size={36} color="#334155" />
                        <span style={{ fontSize: '15px' }}>탐지된 위협 없음</span>
                        <span style={{ fontSize: '12px', color: '#334155' }}>IPS가 실행되면 탐지 로그가 여기에 표시됩니다</span>
                      </div>
                    </td>
                  </tr>
                ) : feedRows.map(({ log, key, isNew }) => {
                  const level = LEVELS[threatLevel(log)];
                  const pct = Math.round((log.confidence || 0) * 100);
                  return (
                    <tr key={key} className={isNew ? 'row-new' : undefined}>
                      <td style={{ ...styles.td, color: '#94a3b8', fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>{log.timestamp}</td>
                      <td style={styles.td}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', fontWeight: 'bold', color: log.is_attack ? '#f1f5f9' : log.attack_type === 'Suspicious' ? level.color : '#22c55e' }}>
                          <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: log.is_attack ? (ATTACK_COLORS[log.attack_type] || '#64748b') : log.attack_type === 'Suspicious' ? level.color : '#22c55e' }} />
                          {log.attack_type === 'Suspicious' ? '미분류 의심' : log.attack_type}
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
          </div>
        </section>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', minWidth: 0 }}>
          <section style={styles.panel}>
            <div style={styles.panelHeader}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                🚫 차단 관리 {blockedIps.length > 0 && <span style={styles.countBadge('#ef4444')}>{blockedIps.length}</span>}
              </span>
              <span style={styles.panelHint}>기본 10분 후 자동 해제</span>
            </div>
            <div className="scroll-y" style={{ maxHeight: '250px' }}>
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
                    {item.attack_type} · {item.blocked_at}{!item.permanent && ` → ${item.auto_unblock_at} 해제`}
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

          <section style={{ ...styles.panel, flex: 1 }}>
            <div style={styles.panelHeader}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                👁 감시목록 {watchlist.length > 0 && <span style={styles.countBadge('#06b6d4')}>{watchlist.length}</span>}
              </span>
              <span style={styles.panelHint}>신뢰도 +20% 가중 적용</span>
            </div>
            <div className="scroll-y" style={{ maxHeight: '200px' }}>
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
        </div>
      </div>

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
          <div className="scroll-y" style={{ maxHeight: '300px' }}>
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
    </div>
  );
}

export default App;
