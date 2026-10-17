import React from 'react';
import { StatCards } from './StatCards';
import { ActivityChart } from './ActivityChart';
import { SeverityChart } from './SeverityChart';
import { TopEntitiesTable } from './TopEntitiesTable';
import { RecentSuspiciousFeed } from './RecentSuspiciousFeed';
import { PrivacyNotice } from '../common/PrivacyNotice';
import { useAnalysis } from '../../context/AnalysisContext';
import { EmptyState } from '../common/EmptyState';
import type { ParsedEvent } from '../../types';

interface DashboardOverviewProps {
  onNavigateFindings: () => void;
  onNavigateEvents: () => void;
  onSelectEvent: (event: ParsedEvent) => void;
  onOpenIngest: () => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  onNavigateFindings,
  onNavigateEvents,
  onSelectEvent,
  onOpenIngest,
}) => {
  const { analysis, setFilterState } = useAnalysis();

  if (!analysis) {
    return <EmptyState onOpenIngest={onOpenIngest} />;
  }

  const handleSelectIp = (ip: string) => {
    setFilterState(prev => ({ ...prev, sourceIp: ip }));
    onNavigateEvents();
  };

  const handleSelectUser = (user: string) => {
    setFilterState(prev => ({ ...prev, username: user }));
    onNavigateEvents();
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-150">
      {/* Top Banner / Privacy Guarantee */}
      <PrivacyNotice />

      {/* Primary KPI Cards */}
      <StatCards
        analysis={analysis}
        onNavigateFindings={onNavigateFindings}
        onNavigateEvents={onNavigateEvents}
      />

      {/* Visual Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart (2 cols) */}
        <div className="lg:col-span-2 bg-navy-900/80 border border-navy-700/80 rounded-xl p-5 shadow-md">
          <div className="flex items-center justify-between pb-3 border-b border-navy-800 mb-4">
            <div>
              <h3 className="text-xs font-mono uppercase tracking-wider text-gray-300 font-semibold">
                Event Activity Over Time
              </h3>
              <p className="text-[11px] text-gray-500">Hourly event distribution extracted from timestamps</p>
            </div>
            <span className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
              {analysis.summary.timeline.length} time buckets
            </span>
          </div>
          <ActivityChart timeline={analysis.summary.timeline} />
        </div>

        {/* Severity Distribution (1 col) */}
        <div className="bg-navy-900/80 border border-navy-700/80 rounded-xl p-5 shadow-md">
          <div className="flex items-center justify-between pb-3 border-b border-navy-800 mb-4">
            <div>
              <h3 className="text-xs font-mono uppercase tracking-wider text-gray-300 font-semibold">
                Rule Severity Breakdown
              </h3>
              <p className="text-[11px] text-gray-500">Security findings by risk tier</p>
            </div>
            <span className="text-[11px] font-mono text-gray-400">
              {analysis.summary.total_findings} total
            </span>
          </div>
          <SeverityChart counts={analysis.summary.severity_counts} />
        </div>
      </div>

      {/* Top Entities (IPs & Usernames) */}
      <TopEntitiesTable
        topIps={analysis.summary.top_source_ips}
        topUsers={analysis.summary.top_usernames}
        onSelectIp={handleSelectIp}
        onSelectUser={handleSelectUser}
      />

      {/* Recent Suspicious Feed */}
      <RecentSuspiciousFeed
        events={analysis.events}
        onSelectEvent={onSelectEvent}
        onViewAll={() => {
          setFilterState(prev => ({ ...prev, suspiciousOnly: true }));
          onNavigateEvents();
        }}
      />
    </div>
  );
};
