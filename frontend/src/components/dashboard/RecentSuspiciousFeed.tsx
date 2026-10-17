import React from 'react';
import { AlertCircle, ArrowRight, Shield } from 'lucide-react';
import type { ParsedEvent } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';

interface RecentSuspiciousFeedProps {
  events: ParsedEvent[];
  onSelectEvent: (event: ParsedEvent) => void;
  onViewAll: () => void;
}

export const RecentSuspiciousFeed: React.FC<RecentSuspiciousFeedProps> = ({
  events,
  onSelectEvent,
  onViewAll,
}) => {
  const suspiciousEvents = events.filter(e => e.is_suspicious).slice(0, 5);

  return (
    <div className="bg-navy-900/80 border border-navy-700/80 rounded-xl p-5 shadow-md">
      <div className="flex items-center justify-between pb-3 border-b border-navy-800 mb-3">
        <div className="flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-orange-400" />
          <h3 className="text-xs font-mono uppercase tracking-wider text-gray-300 font-semibold">
            Suspicious Event Activity Feed
          </h3>
        </div>
        <button
          onClick={onViewAll}
          className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
        >
          <span>View All in Explorer</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {suspiciousEvents.length === 0 ? (
        <div className="py-8 text-center text-xs text-gray-500 font-mono">
          <Shield className="w-6 h-6 text-emerald-400/50 mx-auto mb-2" />
          No suspicious anomalies flagged in current dataset
        </div>
      ) : (
        <div className="space-y-2.5">
          {suspiciousEvents.map(event => (
            <div
              key={event.id}
              onClick={() => onSelectEvent(event)}
              className="p-3 rounded-lg bg-navy-950/40 hover:bg-navy-800/60 border border-navy-800/80 hover:border-cyan-500/40 transition-all cursor-pointer text-xs"
            >
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={event.severity} size="sm" />
                  {event.detection_ids.map(ruleId => (
                    <span
                      key={ruleId}
                      className="px-1.5 py-0.2 rounded bg-navy-800 text-[10px] font-mono text-cyan-400 border border-navy-700"
                    >
                      {ruleId}
                    </span>
                  ))}
                </div>
                <span className="font-mono text-[10px] text-gray-500">
                  {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'Line ' + (event.line_number ?? '')}
                </span>
              </div>
              <p className="font-mono text-gray-300 truncate text-[11px] leading-relaxed">
                {event.raw_message}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
