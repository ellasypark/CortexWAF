import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import './App.css';
import { ThemeProvider, useTheme } from './theme/ThemeContext';
import Header from './components/Header';
import GeoMap from './components/GeoMap';
import HourlyChart from './components/HourlyChart';
import AttackTypeChart from './components/AttackTypeChart';
import RuleManagement from './components/RuleManagement';
import LogTable from './components/LogTable';
import RagRecommendations from './components/RagRecommendations';
import DetailedAnalysis from './components/DetailedAnalysis';

// ★ 날짜 필터 컴포넌트 (그리드 위 우측)
function DateFilter({ dateRange, onDateRangeChange }) {
  const handlePreset = (days) => {
    onDateRangeChange({ type: 'preset', days, startDate: '', endDate: '' });
  };

  const handleCustomDate = (field, value) => {
    onDateRangeChange(prev => {
      const updated = { ...prev, type: 'custom', [field]: value };
      return updated;
    });
  };

  return (
    <div className="date-filter-bar">
      <div className="date-presets">
        {[
          { label: '오늘', days: 1 },
          { label: '7일', days: 7 },
          { label: '30일', days: 30 },
          { label: '전체', days: 0 },
        ].map(({ label, days }) => (
          <button
            key={days}
            className={`preset-btn ${dateRange.type === 'preset' && dateRange.days === days ? 'active' : ''}`}
            onClick={() => handlePreset(days)}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="date-custom">
        <input
          type="date"
          value={dateRange.startDate || ''}
          onChange={(e) => handleCustomDate('startDate', e.target.value)}
          className={`date-input ${dateRange.type === 'custom' ? 'active' : ''}`}
        />
        <span className="date-separator">~</span>
        <input
          type="date"
          value={dateRange.endDate || ''}
          onChange={(e) => handleCustomDate('endDate', e.target.value)}
          className={`date-input ${dateRange.type === 'custom' ? 'active' : ''}`}
        />
      </div>
    </div>
  );
}

function AppContent() {
  const { isDarkMode } = useTheme();
  const [geoData, setGeoData] = useState({});
  const [hourlyData, setHourlyData] = useState({});
  const [attackTypeData, setAttackTypeData] = useState({});
  const [attackTypeColors, setAttackTypeColors] = useState({});
  const [aiRules, setAiRules] = useState([]);
  const [logs, setLogs] = useState([]);
  const [currentView, setCurrentView] = useState('dashboard');

  // ★ 시간대 필터 상태 (기본: 7일)
  const [dateRange, setDateRange] = useState({
    type: 'preset',
    days: 7,
    startDate: '',
    endDate: '',
  });

  const filterLogsByDate = useCallback((allLogs, range) => {
    if (range.type === 'preset' && range.days === 0) return allLogs;
    const now = new Date();
    let startTime, endTime;
    if (range.type === 'preset') {
      startTime = new Date(now);
      startTime.setDate(now.getDate() - range.days);
      endTime = now;
    } else {
      startTime = range.startDate ? new Date(range.startDate + 'T00:00:00') : null;
      endTime   = range.endDate   ? new Date(range.endDate   + 'T23:59:59') : null;
    }
    return allLogs.filter(log => {
      const logTime = new Date(log.timestamp);
      if (startTime && logTime < startTime) return false;
      if (endTime   && logTime > endTime)   return false;
      return true;
    });
  }, []);

  const loadAllData = useCallback(async (range) => {
    try {
      const days = range.type === 'preset' ? (range.days || 30) : 30;
      const params = {};
      if (range.type === 'preset' && range.days > 0) params.days = range.days;
      if (range.type === 'custom' && range.startDate) params.start_date = range.startDate;
      if (range.type === 'custom' && range.endDate)   params.end_date   = range.endDate;

      const [geo, hourly, attackType, after, logsData] = await Promise.all([
        axios.get('/api/geographic-data',    { params }),
        axios.get('/api/hourly-attacks',     { params: { days } }),
        axios.get('/api/monthly-attack-types', { params }),
        axios.get('/api/rules/after'),
        axios.get('/api/logs', { params: { page: 1, per_page: 10000 } })
      ]);

      setGeoData(geo.data);
      setHourlyData(hourly.data);
      setAttackTypeData(attackType.data.data || attackType.data);
      setAttackTypeColors(attackType.data.colors || {});
      setAiRules(after.data.rules);

      const allLogs = logsData.data.logs;
      setLogs(filterLogsByDate(allLogs, range));

    } catch (error) {
      console.error('데이터 로드 오류:', error);
    }
  }, [filterLogsByDate]);

  useEffect(() => {
    const path = window.location.pathname;
    if (path === '/detailed-analysis') {
      setCurrentView('detailed');
    } else {
      setCurrentView('dashboard');
      loadAllData(dateRange);
    }
    const handlePopState = () => {
      const p = window.location.pathname;
      setCurrentView(p === '/detailed-analysis' ? 'detailed' : 'dashboard');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // ★ 날짜 필터 변경 핸들러
  const handleDateRangeChange = useCallback((newRange) => {
    setDateRange(prev => {
      const updated = typeof newRange === 'function' ? newRange(prev) : newRange;
      if (updated.type === 'custom') {
        // 둘 다 입력됐을 때만 로드
        if (updated.startDate && updated.endDate) {
          loadAllData(updated);
        }
      } else {
        loadAllData(updated);
      }
      return updated;
    });
  }, [loadAllData]);

  // 보고서 다운로드 (날짜 파라미터 포함)
  const downloadReport = useCallback(() => {
    const params = new URLSearchParams();
    if (dateRange.type === 'preset' && dateRange.days > 0) {
      params.append('days', dateRange.days);
    } else if (dateRange.type === 'custom') {
      if (dateRange.startDate) params.append('start_date', dateRange.startDate);
      if (dateRange.endDate)   params.append('end_date',   dateRange.endDate);
    }
    const qs = params.toString();
    window.open(`http://localhost:5000/api/download-report${qs ? '?' + qs : ''}`, '_blank');
  }, [dateRange]);

  if (currentView === 'detailed') {
    return <DetailedAnalysis />;
  }

  return (
    <div className="App">
      <Header
        onDownloadReport={downloadReport}
        isDarkMode={isDarkMode}
      />

      <div className="container">
        {/* ★ 날짜 필터 바 - 그리드 위 우측 */}
        <div className="section-filter-row">
          <DateFilter
            dateRange={dateRange}
            onDateRangeChange={handleDateRangeChange}
          />
        </div>

        {/* 최상단: 지도, 시간대별 공격, 월별 공격 유형 */}
        <div className="grid grid-3">
          <GeoMap data={geoData} isDarkMode={isDarkMode} />
          <HourlyChart data={hourlyData} isDarkMode={isDarkMode} />
          <AttackTypeChart data={attackTypeData} isDarkMode={isDarkMode} />
        </div>

        {/* 중앙: WAF 룰 관리 */}
        <RuleManagement
          aiRules={aiRules}
          attackTypeColors={attackTypeColors}
          isDarkMode={isDarkMode}
        />

        <RagRecommendations />

        {/* 최하단: 로그 테이블 */}
        <LogTable logs={logs} />
      </div>
    </div>
  );
}

function App() {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  );
}

export default App;