import React, { useState } from 'react';
import { ArrowRight, Table } from 'lucide-react';

interface CSVColumnMapperProps {
  headers: string[];
  initialMapping?: Record<string, string>;
  onApply: (mapping: Record<string, string>) => void;
  onCancel: () => void;
}

const TARGET_FIELDS: Array<{ key: string; label: string; required?: boolean }> = [
  { key: 'timestamp', label: 'Timestamp (Event Time)' },
  { key: 'source_ip', label: 'Source IP Address' },
  { key: 'username', label: 'Username / Account' },
  { key: 'message', label: 'Raw Message / Description' },
  { key: 'severity', label: 'Severity / Level' },
  { key: 'status', label: 'Status Code (HTTP / Audit)' },
  { key: 'hostname', label: 'Hostname / Computer' },
];

export const CSVColumnMapper: React.FC<CSVColumnMapperProps> = ({
  headers,
  initialMapping = {},
  onApply,
  onCancel,
}) => {
  const [mapping, setMapping] = useState<Record<string, string>>(initialMapping);

  const handleSelect = (fieldKey: string, headerVal: string) => {
    setMapping(prev => ({
      ...prev,
      [fieldKey]: headerVal,
    }));
  };

  const handleSave = () => {
    onApply(mapping);
  };

  return (
    <div className="p-4 bg-navy-950 border border-navy-700 rounded-xl space-y-4">
      <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm border-b border-navy-800 pb-2">
        <Table className="w-4 h-4" />
        <span>Map CSV Columns to Normalized Log Fields</span>
      </div>

      <p className="text-xs text-gray-400">
        Match the column names detected in your CSV header to the internal event fields.
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {TARGET_FIELDS.map(({ key, label }) => (
          <div key={key} className="space-y-1">
            <label className="text-[11px] font-mono text-gray-300 flex items-center justify-between">
              <span>{label}</span>
              {mapping[key] && (
                <span className="text-[10px] text-cyan-400 font-sans">mapped</span>
              )}
            </label>
            <div className="flex items-center gap-2">
              <select
                value={mapping[key] || ''}
                onChange={(e) => handleSelect(key, e.target.value)}
                className="w-full bg-navy-900 border border-navy-700 text-gray-200 text-xs rounded-lg px-2.5 py-1.5 focus:border-cyan-500 focus:outline-none font-mono"
              >
                <option value="">-- Unmapped --</option>
                {headers.map((h) => (
                  <option key={h} value={h}>
                    {h}
                  </option>
                ))}
              </select>
            </div>
          </div>
        ))}
      </div>

      <div className="flex justify-end gap-2 pt-3 border-t border-navy-800">
        <button
          type="button"
          onClick={onCancel}
          className="px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200 transition-colors"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={handleSave}
          className="flex items-center gap-1.5 px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-navy-950 text-xs font-semibold rounded-lg transition-colors"
        >
          <span>Apply Column Mapping</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};
