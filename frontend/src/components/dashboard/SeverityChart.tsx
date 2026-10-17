import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

interface SeverityChartProps {
  counts: Record<string, number>;
}

const SEVERITY_ORDER = [
  { key: 'critical', label: 'Critical', color: '#ef4444' },
  { key: 'high', label: 'High', color: '#f97316' },
  { key: 'medium', label: 'Medium', color: '#eab308' },
  { key: 'low', label: 'Low', color: '#3b82f6' },
  { key: 'informational', label: 'Info', color: '#6b7280' },
];

export const SeverityChart: React.FC<SeverityChartProps> = ({ counts }) => {
  const data = SEVERITY_ORDER.map(({ key, label, color }) => ({
    name: label,
    count: counts[key] || 0,
    color,
  }));

  const total = data.reduce((acc, d) => acc + d.count, 0);

  if (total === 0) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-xs text-gray-500 font-mono">
        <span className="text-emerald-400 font-semibold mb-1">Zero Security Findings</span>
        <span>Baseline activity within normal parameters</span>
      </div>
    );
  }

  return (
    <div className="w-full h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 10, right: 30, left: 10, bottom: 0 }}>
          <XAxis type="number" stroke="#6b7280" fontSize={10} allowDecimals={false} hide />
          <YAxis
            type="category"
            dataKey="name"
            stroke="#9ca3af"
            fontSize={11}
            tickLine={false}
            axisLine={false}
            width={65}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#0f1629',
              borderColor: '#1e2a4a',
              borderRadius: '8px',
              fontSize: '12px',
              color: '#e5e7eb',
            }}
            formatter={(val: unknown) => [`${val} findings`, 'Count']}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
