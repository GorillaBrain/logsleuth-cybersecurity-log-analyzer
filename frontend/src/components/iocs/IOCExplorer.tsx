import React, { useState } from 'react';
import {
  Search,
  Download,
  Copy,
  Check,
  Globe,
  Link,
  Mail,
  Hash,
  Shield,
  ArrowRight,
} from 'lucide-react';
import type { IOC, IOCType } from '../../types';
import { exportIOCsToCSV, exportIOCsToJSON } from '../../services/exportUtils';

interface IOCExplorerProps {
  iocs: IOC[];
  onSelectIndicator: (value: string) => void;
}

export const IOCExplorer: React.FC<IOCExplorerProps> = ({ iocs, onSelectIndicator }) => {
  const [selectedType, setSelectedType] = useState<IOCType | 'all'>('all');
  const [search, setSearch] = useState('');
  const [copiedVal, setCopiedVal] = useState<string | null>(null);

  const filteredIOCs = iocs.filter(ioc => {
    if (selectedType !== 'all' && ioc.ioc_type !== selectedType) return false;
    if (search && !ioc.value.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const handleCopy = (val: string) => {
    void navigator.clipboard.writeText(val);
    setCopiedVal(val);
    setTimeout(() => setCopiedVal(null), 2000);
  };

  const getTypeIcon = (type: IOCType) => {
    switch (type) {
      case 'ipv4':
        return <Globe className="w-3.5 h-3.5 text-cyan-400" />;
      case 'domain':
      case 'url':
        return <Link className="w-3.5 h-3.5 text-teal-400" />;
      case 'email':
        return <Mail className="w-3.5 h-3.5 text-purple-400" />;
      case 'md5':
      case 'sha1':
      case 'sha256':
        return <Hash className="w-3.5 h-3.5 text-amber-400" />;
      default:
        return <Shield className="w-3.5 h-3.5 text-gray-400" />;
    }
  };

  return (
    <div className="space-y-4 animate-in fade-in duration-150">
      {/* Header Toolbar */}
      <div className="p-4 bg-navy-900/90 border border-navy-700/80 rounded-xl shadow-md space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-gray-100 flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              <span>Extracted Indicators of Compromise (IOCs)</span>
            </h2>
            <p className="text-xs text-gray-400">
              Syntactically verified network, domain, and cryptographic observables parsed from log messages
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => exportIOCsToCSV(filteredIOCs)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-navy-800 hover:bg-navy-700 border border-navy-700 text-gray-200 rounded-lg text-xs font-mono transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>CSV</span>
            </button>
            <button
              onClick={() => exportIOCsToJSON(filteredIOCs)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-navy-800 hover:bg-navy-700 border border-navy-700 text-gray-200 rounded-lg text-xs font-mono transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>JSON</span>
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-1 border-t border-navy-800">
          <div className="flex flex-wrap items-center gap-1.5 bg-navy-950 p-1 rounded-lg border border-navy-800 text-xs font-mono">
            {(['all', 'ipv4', 'domain', 'url', 'email', 'sha256', 'md5'] as const).map(t => (
              <button
                key={t}
                onClick={() => setSelectedType(t as IOCType | 'all')}
                className={`px-2.5 py-1 rounded-md uppercase text-[11px] transition-all ${
                  selectedType === t
                    ? 'bg-cyan-600 text-navy-950 font-bold'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          <div className="relative sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              placeholder="Search indicators..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-navy-950 border border-navy-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>
      </div>

      {/* IOC Table */}
      <div className="bg-navy-900/90 border border-navy-700/80 rounded-xl overflow-hidden shadow-md">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-navy-800 bg-navy-950/80 text-gray-400 font-mono text-[11px]">
                <th className="py-3 px-4 w-28">Type</th>
                <th className="py-3 px-4">Observable Indicator</th>
                <th className="py-3 px-4 w-24 text-center">Frequency</th>
                <th className="py-3 px-4 w-32">Classification</th>
                <th className="py-3 px-4 w-44">First / Last Seen</th>
                <th className="py-3 px-4 w-24 text-center">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-800/60 font-mono">
              {filteredIOCs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-gray-500 text-xs">
                    No indicators match the selected filter
                  </td>
                </tr>
              ) : (
                filteredIOCs.map(ioc => (
                  <tr key={`${ioc.ioc_type}-${ioc.value}`} className="hover:bg-navy-800/50 transition-colors">
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1.5 font-bold uppercase text-[10px] text-gray-300">
                        {getTypeIcon(ioc.ioc_type)}
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-semibold text-gray-200 break-all select-all">
                      {ioc.value}
                    </td>
                    <td className="py-2.5 px-4 text-center">
                      <span className="px-2 py-0.5 rounded-full bg-navy-950 text-cyan-400 border border-navy-800 font-bold text-[11px]">
                        {ioc.count}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      {ioc.ioc_type === 'ipv4' ? (
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded border ${
                            ioc.is_private
                              ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                              : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          }`}
                        >
                          {ioc.is_private ? 'RFC1918 Private' : 'Public IP'}
                        </span>
                      ) : (
                        <span className="text-[10px] text-gray-500">Observable</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 text-gray-400 text-[11px] whitespace-nowrap">
                      {ioc.first_seen ? new Date(ioc.first_seen).toLocaleTimeString() : 'N/A'}
                    </td>
                    <td className="py-2.5 px-4 text-center whitespace-nowrap">
                      <div className="flex items-center justify-center gap-1.5">
                        <button
                          onClick={() => handleCopy(ioc.value)}
                          className="p-1.5 text-gray-400 hover:text-cyan-400 rounded hover:bg-navy-800 transition-colors"
                          title="Copy indicator value"
                        >
                          {copiedVal === ioc.value ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                        <button
                          onClick={() => onSelectIndicator(ioc.value)}
                          className="p-1.5 text-gray-400 hover:text-cyan-400 rounded hover:bg-navy-800 transition-colors"
                          title="View all events with this indicator"
                        >
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
