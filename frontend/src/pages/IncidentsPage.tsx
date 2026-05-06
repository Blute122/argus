import { useState, useEffect } from 'react';
import { getIncidents, createIncident, updateIncidentStatus, getIncidentNotes, addIncidentNote, getUsers } from '../services/api';

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [notes, setNotes] = useState<any[]>([]);
  const [newNote, setNewNote] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [, setUsers] = useState<any[]>([]);
  const [form, setForm] = useState({ title: '', description: '', severity: 'medium', category: '' });

  useEffect(() => {
    loadIncidents();
    getUsers().then((r) => setUsers(r.data)).catch(() => {});
  }, []);

  const loadIncidents = () => {
    getIncidents().then((r) => setIncidents(r.data)).catch(() => {});
  };

  const loadNotes = (id: number) => {
    getIncidentNotes(id).then((r) => setNotes(r.data)).catch(() => {});
  };

  const selectIncident = (inc: any) => {
    setSelected(inc);
    loadNotes(inc.id);
  };

  const handleCreate = async () => {
    await createIncident(form);
    setShowCreate(false);
    setForm({ title: '', description: '', severity: 'medium', category: '' });
    loadIncidents();
  };

  const handleStatus = async (id: number, status: string) => {
    await updateIncidentStatus(id, status);
    loadIncidents();
    if (selected?.id === id) setSelected({ ...selected, status });
  };

  const handleAddNote = async () => {
    if (!newNote.trim() || !selected) return;
    await addIncidentNote(selected.id, { content: newNote, note_type: 'general' });
    setNewNote('');
    loadNotes(selected.id);
  };

  const statusColors: Record<string, string> = {
    open: 'status-new', investigating: 'status-investigating',
    contained: 'status-contained', resolved: 'status-resolved', closed: 'status-closed',
  };
  const sevColors: Record<string, string> = {
    critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium', low: 'severity-low',
  };

  const statuses = ['open', 'investigating', 'contained', 'resolved', 'closed'];

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">📋 Incident Response</h1>
          <p className="text-sm text-[var(--text-muted)] font-mono">Track, investigate, and resolve security incidents</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn-primary">+ New Incident</button>
      </div>

      {/* Create modal */}
      {showCreate && (
        <div className="glass-card p-5 space-y-3">
          <h3 className="text-lg font-bold">Create Incident</h3>
          <input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })}
            placeholder="Incident title" className="input-field" />
          <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })}
            placeholder="Description..." className="input-field h-24 resize-none" />
          <div className="flex gap-2">
            <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}
              className="input-field w-auto">
              <option value="critical">Critical</option><option value="high">High</option>
              <option value="medium">Medium</option><option value="low">Low</option>
            </select>
            <input value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}
              placeholder="Category (e.g. malware)" className="input-field" />
          </div>
          <div className="flex gap-2">
            <button onClick={handleCreate} className="btn-primary">Create</button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg border border-[var(--border-color)] text-[var(--text-muted)]">Cancel</button>
          </div>
        </div>
      )}

      <div className="flex gap-4">
        {/* Incident list */}
        <div className="flex-1 space-y-2 max-h-[calc(100vh-220px)] overflow-y-auto pr-2">
          {incidents.map((inc) => (
            <div
              key={inc.id}
              onClick={() => selectIncident(inc)}
              className={`glass-card p-4 cursor-pointer ${selected?.id === inc.id ? 'border-[var(--accent-cyan)]' : ''}`}
            >
              <div className="flex items-center gap-2 mb-2">
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${sevColors[inc.severity] || ''}`}>
                  {inc.severity?.toUpperCase()}
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${statusColors[inc.status] || ''}`}>
                  {inc.status?.toUpperCase()}
                </span>
                <span className="text-sm font-medium flex-1 truncate">{inc.title}</span>
                <span className="text-xs text-[var(--text-muted)] font-mono">#{inc.id}</span>
              </div>
              <p className="text-xs text-[var(--text-secondary)] truncate">{inc.description}</p>
              {inc.sla_deadline && (
                <div className="flex items-center gap-1 mt-2">
                  <span className="text-[10px] text-[var(--text-muted)] font-mono">SLA:</span>
                  <span className="text-[10px] font-mono text-[var(--accent-yellow)]">
                    {new Date(inc.sla_deadline).toLocaleString()}
                  </span>
                </div>
              )}
            </div>
          ))}
          {incidents.length === 0 && (
            <p className="text-center py-12 text-[var(--text-muted)] font-mono">No incidents — click "New Incident"</p>
          )}
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="w-[400px] glass-card p-5 max-h-[calc(100vh-220px)] overflow-y-auto animate-slide-in">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold">INC-{selected.id}</h3>
              <button onClick={() => setSelected(null)} className="text-[var(--text-muted)] hover:text-white text-lg">✕</button>
            </div>

            <div className="space-y-3 text-sm">
              <div className="flex gap-2">
                <span className={`text-xs font-bold px-2 py-0.5 rounded ${sevColors[selected.severity]}`}>{selected.severity?.toUpperCase()}</span>
                <span className={`text-xs font-mono px-2 py-0.5 rounded ${statusColors[selected.status]}`}>{selected.status?.toUpperCase()}</span>
              </div>
              <div><label className="text-[var(--text-muted)] text-xs font-mono">TITLE</label><p className="font-medium">{selected.title}</p></div>
              <div><label className="text-[var(--text-muted)] text-xs font-mono">DESCRIPTION</label><p className="text-[var(--text-secondary)]">{selected.description}</p></div>

              {/* Status workflow */}
              <div>
                <label className="text-[var(--text-muted)] text-xs font-mono mb-1 block">UPDATE STATUS</label>
                <div className="flex flex-wrap gap-1">
                  {statuses.map((s) => (
                    <button key={s} onClick={() => handleStatus(selected.id, s)}
                      className={`text-[10px] font-mono px-2 py-1 rounded border transition-all ${
                        selected.status === s ? 'border-[var(--accent-cyan)] text-[var(--accent-cyan)]' : 'border-[var(--border-color)] text-[var(--text-muted)] hover:text-white'
                      }`}>
                      {s.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              {/* Notes / Timeline */}
              <div className="border-t border-[var(--border-color)] pt-3">
                <label className="text-[var(--text-muted)] text-xs font-mono mb-2 block">INVESTIGATION NOTES</label>
                <div className="space-y-2 mb-3 max-h-[200px] overflow-y-auto">
                  {notes.map((n: any) => (
                    <div key={n.id} className="p-2 rounded bg-[var(--bg-input)] border border-[var(--border-color)] text-xs">
                      <p className="text-[var(--text-secondary)]">{n.content}</p>
                      <span className="text-[10px] text-[var(--text-muted)] font-mono">
                        {n.created_at ? new Date(n.created_at).toLocaleString() : ''}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2">
                  <input value={newNote} onChange={(e) => setNewNote(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAddNote()}
                    placeholder="Add a note..." className="input-field text-sm flex-1" />
                  <button onClick={handleAddNote} className="btn-primary text-xs py-2 px-3">Add</button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
