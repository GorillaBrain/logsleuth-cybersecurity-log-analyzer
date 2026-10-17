import React, { useState, useMemo } from 'react';
import {
  Search,
  Download,
  ChevronLeft,
  ChevronRight,
  Eye,
  RotateCcw,
} from 'lucide-react';
import type { ParsedEvent, Severity, EventCategory } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { EventDetailModal } from './EventDetailModal';
import { exportEventsToCSV } from '../../services/exportUtils';
import { useAnalysis } from '../../context/AnalysisContext';

interface EventExplorerProps {
  events: ParsedEvent[];
}

export const EventExplorer: React.FC<EventExplorerProps> = ({ events }) => {
  const { filterState, setFilterState } = useAnalysis();
  const [selectedEvent, setSelectedEvent] = useState<ParsedEvent | null>(null);
  const [pageSize, setPageSize] = useState<number>(25);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');

  // Filter events
  const filteredEvents = useMemo(() => {
    return events.filter(e => {
      // 1. Search
      if (filterState.search) {
        const q = filterState.search.toLowerCase();
        const matches =
          e.raw_message.toLowerCase().includes(q) ||
          (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
          (e.username && e.username.toLowerCase().includes(q)) ||
          (e.http_path && e.http_path.toLowerCase().includes(q)) ||
          (e.event_action && e.event_action.toLowerCase().includes(q)) ||
          (e.hostname && e.hostname.toLowerCase().includes(q));
        if (!matches) return false;
      }

      // 2. Severity
      if (filterState.severity !== 'all' && e.severity !== filterState.severity) {
        return false;
      }

      // 3. Category
      if (filterState.category !== 'all' && e.event_category !== filterState.category) {
        return false;
      }

      // 4. Source IP
      if (filterState.sourceIp && (!e.source_ip || !e.source_ip.includes(filterState.sourceIp))) {
        return false;
      }

      // 5. Username
      if (filterState.username && (!e.username || !e.username.toLowerCase().includes(filterState.username.toLowerCase()))) {
        return false;
      }

      // 6. Suspicious Only
      if (filterState.suspiciousOnly && !e.is_suspicious) {
        return false;
      }

      // 7. HTTP Status
      if (filterState.httpStatus) {
        const statusNum = parseInt(filterState.httpStatus, 10);
        if (!isNaN(statusNum) && e.http_status !== statusNum) {
          return false;
        }
      }

      return true;
    });
  }, [events, filterState]);

  // Sort events
  const sortedEvents = useMemo(() => {
    return [...filteredEvents].sort((a, b) => {
      const ta = a.timestamp ? new Date(a.timestamp).getTime() : (a.line_number || 0);
      const tb = b.timestamp ? new Date(b.timestamp).getTime() : (b.line_number || 0);
      return sortDirection === 'asc' ? ta - tb : tb - ta;
    });
  }, [filteredEvents, sortDirection]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(sortedEvents.length / pageSize));
  const paginatedEvents = sortedEvents.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleResetFilters = () => {
    setFilterState({
      search: '',
      severity: 'all',
      category: 'all',
      sourceIp: '',
      username: '',
      httpStatus: '',
      suspiciousOnly: false,
    });
    setCurrentPage(1);
  };

  return (
    <div className="space-y-4 animate-in fade-in duration-150">
      {/* Filter Toolbar */}
      <div className="p-4 bg-navy-900/90 border border-navy-700/80 rounded-xl space-y-3 shadow-md">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          {/* Search Box */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              placeholder="Filter by keyword, IP, user, path, or command..."
              value={filterState.search}
              onChange={(e) => {
                setFilterState(prev => ({ ...prev, search: e.target.value }));
                setCurrentPage(1);
              }}
              className="w-full bg-navy-950 border border-navy-700 rounded-lg pl-9 pr-4 py-2 text-xs text-gray-200 placeholder:text-gray-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => exportEventsToCSV(filteredEvents)}
              className="flex items-center gap-1.5 px-3 py-2 bg-navy-800 hover:bg-navy-700 text-gray-200 border border-navy-700 rounded-lg text-xs font-mono transition-colors"
              title="Export filtered log events to CSV"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export CSV</span>
            </button>

            <button
              onClick={handleResetFilters}
              className="p-2 bg-navy-800 hover:bg-navy-700 text-gray-400 hover:text-gray-200 border border-navy-700 rounded-lg transition-colors"
              title="Reset all filters"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Dropdowns Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2 text-xs pt-1">
          {/* Severity */}
          <select
            value={filterState.severity}
            onChange={(e) => {
              setFilterState(prev => ({ ...prev, severity: e.target.value as Severity | 'all' }));
              setCurrentPage(1);
            }}
            className="bg-navy-950 border border-navy-700 text-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="all">Severity: All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Info</option>
          </select>

          {/* Category */}
          <select
            value={filterState.category}
            onChange={(e) => {
              setFilterState(prev => ({ ...prev, category: e.target.value as EventCategory | 'all' }));
              setCurrentPage(1);
            }}
            className="bg-navy-950 border border-navy-700 text-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-cyan-500 capitalize"
          >
            <option value="all">Category: All</option>
            <option value="authentication">Authentication</option>
            <option value="authorization">Authorization</option>
            <option value="web_access">Web Access</option>
            <option value="network">Network</option>
            <option value="system">System</option>
            <option value="application">Application</option>
          </select>

          {/* Source IP Filter */}
          <input
            type="text"
            placeholder="IP Filter..."
            value={filterState.sourceIp}
            onChange={(e) => {
              setFilterState(prev => ({ ...prev, sourceIp: e.target.value }));
              setCurrentPage(1);
            }}
            className="bg-navy-950 border border-navy-700 text-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          />

          {/* Username Filter */}
          <input
            type="text"
            placeholder="User Filter..."
            value={filterState.username}
            onChange={(e) => {
              setFilterState(prev => ({ ...prev, username: e.target.value }));
              setCurrentPage(1);
            }}
            className="bg-navy-950 border border-navy-700 text-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          />

          {/* HTTP Status */}
          <input
            type="text"
            placeholder="Status (404/500)..."
            value={filterState.httpStatus}
            onChange={(e) => {
              setFilterState(prev => ({ ...prev, httpStatus: e.target.value }));
              setCurrentPage(1);
            }}
            className="bg-navy-950 border border-navy-700 text-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          />

          {/* Suspicious Only Toggle */}
          <label className="flex items-center gap-2 px-2.5 py-1.5 bg-navy-950 border border-navy-700 rounded-lg text-gray-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={filterState.suspiciousOnly}
              onChange={(e) => {
                setFilterState(prev => ({ ...prev, suspiciousOnly: e.target.checked }));
                setCurrentPage(1);
              }}
              className="accent-cyan-500"
            />
            <span className="text-[11px] font-mono text-orange-400 font-semibold truncate">
              Flagged Only
            </span>
          </label>
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-navy-900/90 border border-navy-700/80 rounded-xl overflow-hidden shadow-md">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-navy-800 bg-navy-950/80 text-gray-400 font-mono text-[11px] select-none">
                <th className="py-3 px-4 w-12 text-center">#</th>
                <th
                  onClick={() => setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc')}
                  className="py-3 px-4 cursor-pointer hover:text-cyan-400 w-36"
                >
                  Timestamp {sortDirection === 'asc' ? '▲' : '▼'}
                </th>
                <th className="py-3 px-4 w-24">Severity</th>
                <th className="py-3 px-4 w-28">Category</th>
                <th className="py-3 px-4 w-32">Source IP</th>
                <th className="py-3 px-4 w-28">Username</th>
                <th className="py-3 px-4 w-20">Status</th>
                <th className="py-3 px-4">Raw Message Preview</th>
                <th className="py-3 px-4 w-16 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-800/60 font-mono">
              {paginatedEvents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-gray-500 text-xs">
                    No log events match the applied filter criteria
                  </td>
                </tr>
              ) : (
                paginatedEvents.map(event => (
                  <tr
                    key={event.id}
                    onClick={() => setSelectedEvent(event)}
                    className={`hover:bg-navy-800/60 cursor-pointer transition-colors ${
                      event.is_suspicious ? 'bg-red-500/5' : ''
                    }`}
                  >
                    <td className="py-2.5 px-4 text-center text-gray-500 text-[11px]">
                      {event.line_number ?? '-'}
                    </td>
                    <td className="py-2.5 px-4 text-gray-300 text-[11px] whitespace-nowrap">
                      {event.timestamp ? event.timestamp.replace('T', ' ').slice(0, 19) : '-'}
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <SeverityBadge severity={event.severity} size="sm" />
                    </td>
                    <td className="py-2.5 px-4 text-gray-400 capitalize text-[11px] whitespace-nowrap">
                      {event.event_category}
                    </td>
                    <td className="py-2.5 px-4 text-cyan-400 font-semibold whitespace-nowrap">
                      {event.source_ip || '-'}
                    </td>
                    <td className="py-2.5 px-4 text-gray-300 whitespace-nowrap">
                      {event.username || '-'}
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      {event.http_status ? (
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            event.http_status >= 400 ? 'text-red-400 bg-red-500/10' : 'text-emerald-400 bg-emerald-500/10'
                          }`}
                        >
                          {event.http_status}
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-gray-300 truncate max-w-xs md:max-w-md text-[11px]">
                      {event.raw_message}
                    </td>
                    <td className="py-2.5 px-4 text-center">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(event);
                        }}
                        className="p-1 rounded text-gray-400 hover:text-cyan-400 hover:bg-navy-700 transition-colors"
                        title="Inspect event details"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="px-4 py-3 border-t border-navy-800 bg-navy-950/60 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-gray-400 font-mono">
          <div className="flex items-center gap-2">
            <span>Showing {paginatedEvents.length} of {sortedEvents.length} events</span>
            <span className="text-gray-600">|</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setCurrentPage(1);
              }}
              className="bg-navy-900 border border-navy-700 text-gray-300 rounded px-2 py-0.5 text-xs focus:outline-none"
            >
              <option value={25}>25 / page</option>
              <option value={50}>50 / page</option>
              <option value={100}>100 / page</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1 rounded bg-navy-800 border border-navy-700 text-gray-300 disabled:opacity-40 hover:bg-navy-700"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span>
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1 rounded bg-navy-800 border border-navy-700 text-gray-300 disabled:opacity-40 hover:bg-navy-700"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Event Detail Inspection Modal */}
      <EventDetailModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />
    </div>
  );
};
