import React from 'react';
import type { Severity } from '../../types';

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
  size?: 'sm' | 'md';
}

const SEVERITY_CONFIG: Record<Severity, { bg: string; text: string; border: string; label: string }> = {
  critical: {
    bg: 'bg-red-500/10',
    text: 'text-red-400',
    border: 'border-red-500/30',
    label: 'CRITICAL',
  },
  high: {
    bg: 'bg-orange-500/10',
    text: 'text-orange-400',
    border: 'border-orange-500/30',
    label: 'HIGH',
  },
  medium: {
    bg: 'bg-amber-500/10',
    text: 'text-amber-400',
    border: 'border-amber-500/30',
    label: 'MEDIUM',
  },
  low: {
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    border: 'border-blue-500/30',
    label: 'LOW',
  },
  informational: {
    bg: 'bg-gray-500/10',
    text: 'text-gray-400',
    border: 'border-gray-500/30',
    label: 'INFO',
  },
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '', size = 'md' }) => {
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.informational;
  const sizeClasses = size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-0.5 text-xs';

  return (
    <span
      className={`inline-flex items-center font-mono font-medium rounded-md border ${config.bg} ${config.text} ${config.border} ${sizeClasses} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current opacity-75" />
      {config.label}
    </span>
  );
};
