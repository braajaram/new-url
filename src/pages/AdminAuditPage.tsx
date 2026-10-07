import React, { useState, useEffect } from 'react';
import { Terminal, Users, Shield, RefreshCw } from 'lucide-react';
import { AuditLogItem } from '../types/threat';

export const AdminAuditPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [users, setUsers] = useState<any[]>([]);

  const fetchData = async () => {
    try {
      const [lRes, uRes] = await Promise.all([
        fetch('/api/admin/logs'),
        fetch('/api/admin/users')
      ]);
      if (lRes.ok) setLogs(await lRes.json());
      if (uRes.ok) setUsers(await uRes.json());
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 font-mono">
      <div>
        <div className="flex items-center space-x-2">
          <h1 className="text-xl font-bold text-white tracking-wide">SOC Administrator & Audit Telemetry</h1>
          <span className="px-2 py-0.5 text-[10px] bg-red-950 text-red-400 border border-red-800 rounded">
            ADMIN LOGS
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1 font-sans">
          Immutable audit logs of all user authentication events, scans, API access, and configuration changes.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Users */}
        <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
          <h3 className="text-xs font-bold text-gray-200 uppercase flex items-center space-x-2">
            <Users size={16} className="text-blue-400" />
            <span>Registered SOC Officers ({users.length})</span>
          </h3>
          <div className="space-y-2 text-xs">
            {users.map(u => (
              <div key={u.id} className="p-2.5 rounded bg-gray-900 border border-gray-800">
                <div className="font-bold text-white">{u.name}</div>
                <div className="text-[10px] text-gray-500">{u.email} &bull; {u.role}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Audit Log Stream */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-xs font-bold text-gray-200 uppercase flex items-center space-x-2">
              <Terminal size={16} className="text-red-400" />
              <span>System Audit Stream</span>
            </h3>
            <button onClick={fetchData} className="text-gray-400 hover:text-white">
              <RefreshCw size={14} />
            </button>
          </div>

          <div className="space-y-2 max-h-[500px] overflow-y-auto">
            {logs.map(log => (
              <div key={log.id} className="p-2.5 rounded bg-gray-900 border border-gray-800 flex justify-between text-xs">
                <div>
                  <div className="text-white font-bold">{log.action}</div>
                  <div className="text-[10px] text-gray-500">
                    User: {log.user} {log.target ? `| Target: ${log.target}` : ''}
                  </div>
                </div>
                <div className="text-right text-[10px] text-gray-500">
                  <div>{log.status}</div>
                  <div>{new Date(log.timestamp).toLocaleTimeString()}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
