import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { ShieldAlert, Activity, BarChart3, Clock, Server, Eye, Trash2 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

const ATTACK_COLORS = {
  BruteForce: '#f97316',
  PortScan:   '#a855f7',
  DDoS:       '#ef4444',
  SQLi:       '#eab308',
  XSS:        '#ec4899',
  Honeypot:   '#06b6d4',
};

const styles = {
  container: { padding: '30px', backgroundColor: '#0f172a', minHeight: '100vh', color: '#f1f5f9', fontFamily: "'Pretendard', sans-serif" },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px', borderBottom: '1px solid #334155', paddingBottom: '20px' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '20px' },
  card: { backgroundColor: '#1e293b', padding: '20px', borderRadius: '16px', border: '1px solid #334155', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)' },
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
  const [attackTypeCounts, setAttackTypeCounts] = useState({});
  const [watchlist, setWatchlist] = useState([]);
  const chartContainerRef = useRef(null);
  const [chartWidth, setChartWidth] = useState(800);

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

  const fetchData = async () => {
    try {
      const [logRes, statRes, statusRes, typeRes, serverLogRes] = await Promise.all([
        axios.get('http://localhost:8000/logs'),
        axios.get('http://localhost:8000/stats'),
        axios.get('http://localhost:8000/ips_status'),
        axios.get('http://localhost:8000/stats/by_type'),
        axios.get('http://localhost:8000/server_logs'),
      ]);
      setLogs(logRes.data);
      setStats(statRes.data);
      setIpsRunning(statusRes.data.running);
      setAttackTypeCounts(typeRes.data);
      setServerLogs(serverLogRes.data.reverse());
      setConnected(true);
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
    setAttackTypeCounts({});
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

  const testResponse = async (level) => {
    await axios.post('http://localhost:8000/test_response', {
      ip: '192.168.219.118', level
    });
  };

  const handleRemoveWatchlist = async (ip) => {
    await axios.post('http://localhost:8000/watchlist/remove', { ip });
    fetchWatchlist();
  };

  useEffect(() => {
    if (chartContainerRef.current) setChartWidth(chartContainerRef.current.offsetWidth);
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
    const interval = setInterval(() => { fetchData(); fetchWatchlist(); }, 5000);

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
        if (newLog.is_attack === true || newLog.is_attack === 1) {
          setAttackTypeCounts(prev => ({
            ...prev,
            [newLog.attack_type]: (prev[newLog.attack_type] || 0) + 1
          }));
          if (newLog.attack_type === 'Honeypot') {
            fetchWatchlist();
          }
          if (newLog.confidence >= 0.9 && Notification.permission === 'granted') {
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
          <div style={{ display: 'flex', gap: '6px' }}>
            {['low','medium','high','critical'].map(level => (
              <button key={level} onClick={() => testResponse(level)} style={{
                padding: '6px 12px', borderRadius: '6px', border: 'none', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold',
                backgroundColor: {low:'#14532d',medium:'#78350f',high:'#7f1d1d',critical:'#4c0519'}[level],
                color: {low:'#86efac',medium:'#fcd34d',high:'#fca5a5',critical:'#f9a8d4'}[level],
              }}>
                TEST {level.toUpperCase()}
              </button>
            ))}
          </div>
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
          <BarChart3 size={20} /> 공격 유형별 탐지 건수
        </div>
        <div ref={chartContainerRef} style={{ width: '100%' }}>
          <BarChart width={chartWidth} height={150}
            data={Object.entries(attackTypeCounts).map(([type, count]) => ({ type, count }))}
            margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
            <XAxis dataKey="type" tick={{ fill: '#94a3b8', fontSize: 12 }} />
            <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', color: '#f1f5f9' }}
              formatter={(value) => [`${value}건`, '탐지 건수']}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {Object.entries(attackTypeCounts).map(([type]) => (
                <Cell key={type} fill={ATTACK_COLORS[type] || '#64748b'} />
              ))}
            </Bar>
          </BarChart>
        </div>
      </div>

      {/* 탭 */}
      <div style={styles.tabBar}>
        <button style={styles.tab(tab === 'logs')} onClick={() => setTab('logs')}>📍 실시간 위협 로그</button>
        <button style={styles.tab(tab === 'server_logs')} onClick={() => setTab('server_logs')}>🖥️ 서버 접속 로그</button>
        <button style={styles.tab(tab === 'watchlist')} onClick={() => setTab('watchlist')}>
          👁 감시목록 {watchlist.length > 0 && <span style={{ marginLeft: '6px', backgroundColor: '#06b6d4', color: '#fff', borderRadius: '10px', padding: '1px 7px', fontSize: '11px' }}>{watchlist.length}</span>}
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
              {logs.map((log, index) => (
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
    </div>
  );
}

export default App;
