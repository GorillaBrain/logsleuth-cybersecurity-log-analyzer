import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';

interface ActivityChartProps {
  timeline: Array<{ time: string; count: number }>;
}

export const ActivityChart: React.FC<ActivityChartProps> = ({ timeline }) => {
  if (!timeline || timeline.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-xs text-gray-500 font-mono">
        No timestamped event distribution available
      </div>
    );
  }

  // Format short labels
  const data = timeline.map(item => ({
    ...item,
    formattedTime: item.time.split(' ')[1] || item.time,
  }));

  return (
    <div className="w-full h-64">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2a4a" vertical={false} />
          <XAxis
            dataKey="formattedTime"
            stroke="#6b7280"
            fontSize={10}
            tickLine={false}
            axisLine={{ stroke: '#1e2a4a' }}
          />
          <YAxis
            stroke="#6b7280"
            fontSize={10}
            tickLine={false}
            axisLine={{ stroke: '#1e2a4a' }}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#0f1629',
              borderColor: '#1e2a4a',
              borderRadius: '8px',
              fontSize: '12px',
              color: '#e5e7eb',
              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)',
            }}
            labelStyle={{ color: '#22d3ee', fontWeight: 'bold' }}
            formatter={(val: unknown) => [`${val} events`, 'Volume']}
          />
          <Area
            type="monotone"
            dataKey="count"
            stroke="#22d3ee"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#eventGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};
