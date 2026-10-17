import React from 'react';
import type { InvestigationStatus } from '../../types';

interface StatusBadgeProps {
  status: InvestigationStatus;
  className?: string;
  size?: 'sm' | 'md';
}

const STATUS_CONFIG: Record<InvestigationStatus, { bg: string; text: string; border: string; label: string }> = {
  new: {
    bg: 'bg-cyan-500/10',
    text: 'text-cyan-400',
    border: 'border-cyan-500/30',
    label: 'New',
  },
  investigating: {
    bg: 'bg-amber-500/10',
    text: 'text-amber-400',
    border: 'border-amber-500/30',
    label: 'Investigating',
  },
  resolved: {
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-400',
    border: 'border-emerald-500/30',
    label: 'Resolved',
  },
  false_positive: {
    bg: 'bg-slate-500/10',
    text: 'text-slate-400',
    border: 'border-slate-500/30',
    label: 'False Positive',
  },
};

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className = '', size = 'md' }) => {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.new;
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center font-medium rounded-full border ${config.bg} ${config.text} ${config.border} ${sizeClasses} ${className}`}
    >
      {config.label}
    </span>
  );
};
