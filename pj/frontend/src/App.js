import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { ShieldAlert, Activity, BarChart3, Clock, Eye, Trash2 } from 'lucide-react';
import bb, { spline } from 'billboard.js';
import 'billboard.js/dist/billboard.css';

const ATTACK_COLORS = {
  BruteForce: '#f97316',
  PortScan:   '#a855f7',
  DDoS:       '#ef4444',
  SQLi:       '#eab308',
  XSS:        '#ec4899',
  Honeypot:   '#06b6d4',
};

const TIMELINE_BUCKET_MS = 10 * 1000;   // 10초 단위로 집계
const TIMELINE_WINDOW_MS = 5 * 60 * 1000; // 최근 5분만 표시

const bucketStart = (tsMs) => Math.floor(tsMs / TIMELINE_BUCKET_MS) * TIMELINE_BUCKET_MS;

// 백엔드 타임스탬프 'YYYY-MM-DD HH:MM:SS' -> epoch ms (로컬 타임존 기준)
const parseTimestamp = (ts) => {
  const t = new Date(ts.replace(' ', 'T')).getTime();
  return Number.isNaN(t) ? Date.now() : t;
};

const styles = {
  container: { padding: '30px', backgroundColor: '#0f172a', minHeight: '100vh', color: '#f1f5f9', fontFamily: "'Pretendard', sans-serif" },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px', borderBottom: '1px solid #334155', paddingBottom: '20px' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '20px', alignItems: 'stretch' },
  card: { backgroundColor: '#1e293b', padding: '28px 32px', borderRadius: '16px', border: '1px solid #334155', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)' },
  tableSection: { backgroundColor: '#1e293b', borderRadius: '16px', border: '1px solid #334155', overflow: 'hidden', marginBottom: '20px' },
  table: { width: '100%', borderCollapse: 'collapse' },
  th: { backgroundColor: '#334155', padding: '15px', textAlign: 'left', fontSize: '14px', color: '#94a3b8' },
  td: { padding: '15px', borderBottom: '1px solid #334155', fontSize: '14px' },
  badge: (blocked) => ({ padding: '4px 10px', borderRadius: '20px', fontSize: '12px', fontWeight: 'bold', backgroundColor: blocked ? '#166534' : '#991b1b', color: '#f8fafc' }),
  tabBar: { display: 'flex', gap: '8px', marginBottom: '20px' },
  tab: (active) => ({
    padding: '8px 20px', borderRadius: '8px', border: 'none', cursor: 'pointer', fontSize: '14px', fontWeight: 'bold',
    backgroundColor: active ? '#3b82f6' : '#334155',
    color: active ? '#fff' : '#94a3b8',
  }),
  threatBadge: (level) => {
    const colors = { high: '#7f1d1d', medium: '#78350f', low: '#14532d', critical: '#4c0519' };
    const textColors = { high: '#fca5a5', medium: '#fcd34d', low: '#86efac', critical: '#f9a8d4' };
    return { padding: '3px 10px', borderRadius: '20px', fontSize: '12px', fontWeight: 'bold', backgroundColor: colors[level] || '#1e293b', color: textColors[level] || '#94a3b8' };
  },
};

function App() {
  const [tab, setTab] = useState('logs');
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
        size: { height: 180 },
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

  useEffect(() => {
    return () => {
      if (chartInstanceRef.current) {
        chartInstanceRef.current.destroy();
        chartInstanceRef.current = null;
      }
    };
  }, []);

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
          if (newLog.attack_type === 'Honeypot') {
            fetchWatchlist();
          }
          if (newLog.blocked && Notification.permission === 'granted') {
            new Notification('🚫 IP 차단됨 — 관리자 검토 필요', {
              body: `${newLog.attack_type} | IP: ${newLog.attacker_ip} | 블랙리스트 등록됨, 검토 후 조치하세요.`,
              icon: '/favicon.ico'
            });
            fetchBlockedIps();
          } else if (newLog.confidence >= 0.9 && Notification.permission === 'granted') {
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

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <h1 style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: 0 }}>
          <ShieldAlert size={32} color="#3b82f6" /> AI 기반 차세대 실시간 IPS
          <span style={{
            fontSize: '12px', fontWeight: 'normal', padding: '3px 10px',
            borderRadius: '20px', marginLeft: '8px',
            backgroundColor: connected ? '#166534' : '#7f1d1d',
            color: connected ? '#86efac' : '#fca5a5'
          }}>
            {connected ? '● 백엔드 연결됨' : '● 연결 끊김'}
          </span>
        </h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {ipsRunning ? (
            <button onClick={handleStop} style={{ padding: '8px 20px', borderRadius: '8px', border: 'none', backgroundColor: '#ef4444', color: '#fff', fontWeight: 'bold', cursor: 'pointer', fontSize: '14px' }}>
              ■ 중지
            </button>
          ) : (
            <button onClick={handleStart} style={{ padding: '8px 20px', borderRadius: '8px', border: 'none', backgroundColor: '#22c55e', color: '#fff', fontWeight: 'bold', cursor: 'pointer', fontSize: '14px' }}>
              ▶ 시작
            </button>
          )}
          <button onClick={handleEmergencyReset} style={{ padding: '8px 20px', borderRadius: '8px', border: 'none', backgroundColor: '#f59e0b', color: '#fff', fontWeight: 'bold', cursor: 'pointer', fontSize: '14px' }}>
            🚨 긴급 해제
          </button>
          <button onClick={enableNotifications} style={{ padding: '8px 16px', borderRadius: '8px', border: 'none', backgroundColor: '#334155', color: '#94a3b8', cursor: 'pointer', fontSize: '13px' }}>
            🔔 알림 허용
          </button>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#94a3b8' }}>
            <Clock size={18} /> {currentTime}
          </div>
        </div>
      </header>

      <div style={styles.grid}>
        <div style={styles.card}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#94a3b8', marginBottom: '10px' }}>
            <Activity size={20} /> 전체 탐지 건수
          </div>
          <div style={{ fontSize: '36px', fontWeight: 'bold', color: '#f1f5f9' }}>{stats.total} <span style={{fontSize: '18px'}}>건</span></div>
        </div>
        <div style={styles.card}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#94a3b8', marginBottom: '10px' }}>
            <ShieldAlert size={20} /> 공격 탐지
          </div>
          <div style={{ fontSize: '36px', fontWeight: 'bold', color: '#ef4444' }}>{stats.attack} <span style={{fontSize: '18px'}}>건</span></div>
        </div>
        <div style={styles.card}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#94a3b8', marginBottom: '10px' }}>
            <Eye size={20} /> 감시목록
          </div>
          <div style={{ fontSize: '36px', fontWeight: 'bold', color: '#06b6d4' }}>{watchlist.length} <span style={{fontSize: '18px'}}>IP</span></div>
        </div>
      </div>

      <div style={{ ...styles.card, marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#94a3b8', marginBottom: '15px' }}>
          <BarChart3 size={20} /> 공격 유형별 탐지 추이 (최근 5분)
        </div>
        <div style={{ position: 'relative', width: '100%' }}>
          {timeline.length === 0 && (
            <div style={{
              position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center', color: '#475569', gap: '8px', zIndex: 1,
            }}>
              <BarChart3 size={32} color="#334155" />
              <span style={{ fontSize: '14px' }}>탐지된 공격 없음</span>
            </div>
          )}
          <div
            ref={chartContainerRef}
            style={{ width: '100%', height: '180px', visibility: timeline.length === 0 ? 'hidden' : 'visible' }}
          />
        </div>
      </div>

      {/* 탭 */}
      <div style={styles.tabBar}>
        <button style={styles.tab(tab === 'logs')} onClick={() => setTab('logs')}>📍 실시간 위협 로그</button>
        <button style={styles.tab(tab === 'server_logs')} onClick={() => setTab('server_logs')}>🖥️ 서버 접속 로그</button>
        <button style={styles.tab(tab === 'watchlist')} onClick={() => setTab('watchlist')}>
          👁 감시목록 {watchlist.length > 0 && <span style={{ marginLeft: '6px', backgroundColor: '#06b6d4', color: '#fff', borderRadius: '10px', padding: '1px 7px', fontSize: '11px' }}>{watchlist.length}</span>}
        </button>
        <button style={styles.tab(tab === 'blocked')} onClick={() => setTab('blocked')}>
          🚫 차단 관리 {blockedIps.length > 0 && <span style={{ marginLeft: '6px', backgroundColor: '#ef4444', color: '#fff', borderRadius: '10px', padding: '1px 7px', fontSize: '11px' }}>{blockedIps.length}</span>}
        </button>
      </div>

      {tab === 'logs' && (
        <section style={styles.tableSection}>
          <div style={{ padding: '20px', borderBottom: '1px solid #334155', fontWeight: 'bold' }}>📍 실시간 보안 위협 로그</div>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>공격 유형</th>
                <th style={styles.th}>공격자 IP</th>
                <th style={styles.th}>탐지 시간</th>
                <th style={styles.th}>위협 레벨</th>
                <th style={styles.th}>방어 상태</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ ...styles.td, textAlign: 'center', padding: '48px', color: '#475569' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
                      <ShieldAlert size={36} color="#334155" />
                      <span style={{ fontSize: '15px' }}>탐지된 위협 없음</span>
                      <span style={{ fontSize: '12px', color: '#334155' }}>IPS가 실행되면 탐지 로그가 여기에 표시됩니다</span>
                    </div>
                  </td>
                </tr>
              ) : logs.map((log, index) => (
                <tr key={index}>
                  <td style={{ ...styles.td, color: log.is_attack ? '#ef4444' : '#22c55e', fontWeight: 'bold' }}>{log.attack_type}</td>
                  <td style={styles.td}>{log.attacker_ip}</td>
                  <td style={styles.td}>{log.timestamp}</td>
                  <td style={styles.td}>{
                    !log.is_attack ? '✅ 정상' :
                    log.confidence >= 0.9 ? '🔴 Critical' :
                    log.confidence >= 0.75 ? '🟠 High' :
                    log.confidence >= 0.6 ? '🟡 Medium' : '🟢 Low'
                  }</td>
                  <td style={styles.td}><span style={styles.badge(log.blocked)}>{log.blocked ? "차단 완료" : "탐지됨"}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {tab === 'server_logs' && (
        <section style={styles.tableSection}>
          <div style={{ padding: '20px', borderBottom: '1px solid #334155', fontWeight: 'bold' }}>🖥️ 서버 접속 로그 (실제 서버 / 허니팟)</div>
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
                  <td style={{ ...styles.td, color: log.payload ? '#eab308' : '#475569', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {log.payload || '-'}
                  </td>
                  <td style={styles.td}>{log.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {tab === 'watchlist' && (
        <section style={styles.tableSection}>
          <div style={{ padding: '20px', borderBottom: '1px solid #334155', fontWeight: 'bold', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>👁 감시목록 — 허니팟/반복 공격 IP 자동 등록</span>
            <span style={{ fontSize: '13px', color: '#94a3b8' }}>신뢰도 +20% 가중 적용</span>
          </div>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>IP 주소</th>
                <th style={styles.th}>등록 사유</th>
                <th style={styles.th}>위협 레벨</th>
                <th style={styles.th}>등록 시각</th>
                <th style={styles.th}>관리</th>
              </tr>
            </thead>
            <tbody>
              {watchlist.length === 0 ? (
                <tr><td colSpan={5} style={{ ...styles.td, textAlign: 'center', color: '#475569' }}>감시 중인 IP 없음</td></tr>
              ) : watchlist.map((item) => (
                <tr key={item.id}>
                  <td style={{ ...styles.td, fontFamily: 'monospace', color: '#06b6d4' }}>{item.ip}</td>
                  <td style={styles.td}>{item.reason}</td>
                  <td style={styles.td}><span style={styles.threatBadge(item.threat_level)}>{item.threat_level.toUpperCase()}</span></td>
                  <td style={styles.td}>{item.added_at}</td>
                  <td style={styles.td}>
                    <button
                      onClick={() => handleRemoveWatchlist(item.ip)}
                      style={{ background: 'none', border: '1px solid #475569', borderRadius: '6px', padding: '4px 8px', cursor: 'pointer', color: '#ef4444' }}
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {tab === 'blocked' && (
        <section style={styles.tableSection}>
          <div style={{ padding: '20px', borderBottom: '1px solid #334155', fontWeight: 'bold', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>🚫 차단된 IP — 관리자 검토 대기</span>
            <span style={{ fontSize: '13px', color: '#94a3b8' }}>기본 10분 후 자동 해제 (영구 차단 선택 시 제외)</span>
          </div>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>IP 주소</th>
                <th style={styles.th}>공격 유형</th>
                <th style={styles.th}>차단 시각</th>
                <th style={styles.th}>상태</th>
                <th style={styles.th}>자동 해제 시각</th>
                <th style={styles.th}>관리자 조치</th>
              </tr>
            </thead>
            <tbody>
              {blockedIps.length === 0 ? (
                <tr><td colSpan={6} style={{ ...styles.td, textAlign: 'center', color: '#475569' }}>현재 차단된 IP 없음</td></tr>
              ) : blockedIps.map((item) => (
                <tr key={item.id}>
                  <td style={{ ...styles.td, fontFamily: 'monospace', color: '#ef4444' }}>{item.ip}</td>
                  <td style={styles.td}>{item.attack_type}</td>
                  <td style={styles.td}>{item.blocked_at}</td>
                  <td style={styles.td}>
                    {item.permanent
                      ? <span style={styles.threatBadge('critical')}>영구 차단</span>
                      : item.reviewed
                        ? <span style={styles.threatBadge('medium')}>검토 완료(10분)</span>
                        : <span style={styles.threatBadge('high')}>검토 대기</span>}
                  </td>
                  <td style={styles.td}>{item.permanent ? '—' : item.auto_unblock_at}</td>
                  <td style={styles.td}>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <button
                        onClick={() => handleBlockedDecision(item.ip, 'keep_10min')}
                        style={{ padding: '4px 10px', borderRadius: '6px', border: '1px solid #475569', background: 'none', color: '#fcd34d', cursor: 'pointer', fontSize: '12px' }}
                      >10분 유지</button>
                      <button
                        onClick={() => handleBlockedDecision(item.ip, 'permanent')}
                        style={{ padding: '4px 10px', borderRadius: '6px', border: '1px solid #475569', background: 'none', color: '#f9a8d4', cursor: 'pointer', fontSize: '12px' }}
                      >영구 차단</button>
                      <button
                        onClick={() => handleBlockedDecision(item.ip, 'unblock')}
                        style={{ padding: '4px 10px', borderRadius: '6px', border: '1px solid #475569', background: 'none', color: '#86efac', cursor: 'pointer', fontSize: '12px' }}
                      >즉시 해제</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}

export default App;
