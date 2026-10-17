import React from 'react';
import { Globe, User } from 'lucide-react';
import { isPrivateIP } from '../../services/clientEngine/ipUtils';

interface TopEntitiesTableProps {
  topIps: Array<{ ip: string; count: number }>;
  topUsers: Array<{ username: string; count: number }>;
  onSelectIp: (ip: string) => void;
  onSelectUser: (user: string) => void;
}

export const TopEntitiesTable: React.FC<TopEntitiesTableProps> = ({
  topIps,
  topUsers,
  onSelectIp,
  onSelectUser,
}) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Top Source IPs */}
      <div className="bg-navy-900/80 border border-navy-700/80 rounded-xl p-5 shadow-md">
        <div className="flex items-center justify-between pb-3 border-b border-navy-800 mb-3">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono uppercase tracking-wider text-gray-300 font-semibold">
              Top Source IP Addresses
            </h3>
          </div>
          <span className="text-[11px] text-gray-500 font-mono">By Frequency</span>
        </div>

        {topIps.length === 0 ? (
          <div className="py-8 text-center text-xs text-gray-500 font-mono">
            No source IP addresses identified
          </div>
        ) : (
          <div className="space-y-2">
            {topIps.slice(0, 5).map(({ ip, count }) => {
              const privateIP = isPrivateIP(ip);
              return (
                <div
                  key={ip}
                  onClick={() => onSelectIp(ip)}
                  className="flex items-center justify-between p-2 rounded-lg bg-navy-950/40 hover:bg-navy-800/60 border border-navy-800/80 hover:border-cyan-500/40 transition-all cursor-pointer group"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-gray-200 group-hover:text-cyan-400">
                      {ip}
                    </span>
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.2 rounded border ${
                        privateIP
                          ? 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                          : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                      }`}
                    >
                      {privateIP ? 'RFC1918' : 'Public'}
                    </span>
                  </div>
                  <span className="font-mono text-xs font-semibold text-gray-400 group-hover:text-gray-200">
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Top Targeted Users */}
      <div className="bg-navy-900/80 border border-navy-700/80 rounded-xl p-5 shadow-md">
        <div className="flex items-center justify-between pb-3 border-b border-navy-800 mb-3">
          <div className="flex items-center gap-2">
            <User className="w-4 h-4 text-teal-400" />
            <h3 className="text-xs font-mono uppercase tracking-wider text-gray-300 font-semibold">
              Targeted Accounts
            </h3>
          </div>
          <span className="text-[11px] text-gray-500 font-mono">By Frequency</span>
        </div>

        {topUsers.length === 0 ? (
          <div className="py-8 text-center text-xs text-gray-500 font-mono">
            No usernames identified in log stream
          </div>
        ) : (
          <div className="space-y-2">
            {topUsers.slice(0, 5).map(({ username, count }) => (
              <div
                key={username}
                onClick={() => onSelectUser(username)}
                className="flex items-center justify-between p-2 rounded-lg bg-navy-950/40 hover:bg-navy-800/60 border border-navy-800/80 hover:border-teal-500/40 transition-all cursor-pointer group"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-gray-200 group-hover:text-teal-400">
                    {username}
                  </span>
                  {['root', 'admin', 'administrator', 'oracle'].includes(username.toLowerCase()) && (
                    <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                      Privileged
                    </span>
                  )}
                </div>
                <span className="font-mono text-xs font-semibold text-gray-400 group-hover:text-gray-200">
                  {count}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
