import { useState, useEffect } from 'react';
import { getMitreTactics, getMitreTechniques } from '../services/api';

export default function MitrePage() {
  const [tactics, setTactics] = useState<any[]>([]);
  const [techniques, setTechniques] = useState<any[]>([]);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<any>(null);

  useEffect(() => {
    getMitreTactics().then((r) => setTactics(r.data)).catch(() => {});
    getMitreTechniques().then((r) => setTechniques(r.data)).catch(() => {});
  }, []);

  const filtered = selectedTactic
    ? techniques.filter((t) => t.tactic === selectedTactic)
    : techniques;

  const sevColors: Record<string, string> = {
    critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium', low: 'severity-low',
  };

  const tacticColors: Record<string, string> = {
    'TA0001': 'from-blue-600 to-blue-400',
    'TA0002': 'from-red-600 to-red-400',
    'TA0003': 'from-purple-600 to-purple-400',
    'TA0004': 'from-orange-600 to-orange-400',
    'TA0005': 'from-yellow-600 to-yellow-400',
    'TA0006': 'from-pink-600 to-pink-400',
    'TA0007': 'from-cyan-600 to-cyan-400',
    'TA0008': 'from-green-600 to-green-400',
    'TA0009': 'from-indigo-600 to-indigo-400',
    'TA0010': 'from-rose-600 to-rose-400',
    'TA0011': 'from-emerald-600 to-emerald-400',
    'TA0040': 'from-red-700 to-red-500',
    'TA0042': 'from-teal-600 to-teal-400',
    'TA0043': 'from-sky-600 to-sky-400',
  };

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold">🗺️ MITRE ATT&CK Framework</h1>
        <p className="text-sm text-[var(--text-muted)] font-mono">
          Tactics, techniques, and procedures mapped to detected threats
        </p>
      </div>

      {/* Tactics bar */}
      <div className="flex gap-2 overflow-x-auto pb-2">
        <button
          onClick={() => setSelectedTactic(null)}
          className={`text-xs font-mono px-3 py-1.5 rounded-lg border transition-all whitespace-nowrap ${
            !selectedTactic
              ? 'border-[var(--accent-cyan)] text-[var(--accent-cyan)] bg-cyan-500/10'
              : 'border-[var(--border-color)] text-[var(--text-muted)] hover:text-white'
          }`}
        >
          All Tactics
        </button>
        {tactics.map((t: any) => (
          <button
            key={t.id}
            onClick={() => setSelectedTactic(t.id)}
            className={`text-xs font-mono px-3 py-1.5 rounded-lg border transition-all whitespace-nowrap ${
              selectedTactic === t.id
                ? 'border-[var(--accent-cyan)] text-[var(--accent-cyan)] bg-cyan-500/10'
                : 'border-[var(--border-color)] text-[var(--text-muted)] hover:text-white'
            }`}
          >
            {t.name}
          </button>
        ))}
      </div>

      <div className="flex gap-4">
        {/* Techniques grid */}
        <div className="flex-1 grid grid-cols-2 gap-3 max-h-[calc(100vh-260px)] overflow-y-auto pr-2 content-start">
          {filtered.map((tech: any) => (
            <div
              key={tech.id}
              onClick={() => setSelectedTechnique(tech)}
              className={`glass-card p-4 cursor-pointer ${selectedTechnique?.id === tech.id ? 'border-[var(--accent-cyan)]' : ''}`}
            >
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs font-mono font-bold text-[var(--accent-cyan)]">{tech.id}</span>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${sevColors[tech.severity] || ''}`}>
                  {tech.severity?.toUpperCase()}
                </span>
              </div>
              <h4 className="text-sm font-semibold mb-1">{tech.name}</h4>
              <p className="text-[11px] text-[var(--text-secondary)] line-clamp-2">{tech.description}</p>
              <div className="mt-2">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded bg-gradient-to-r ${tacticColors[tech.tactic] || 'from-gray-600 to-gray-400'} text-white`}>
                  {tech.tactic_name}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Technique detail */}
        {selectedTechnique && (
          <div className="w-[380px] glass-card p-5 self-start animate-slide-in">
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm font-mono font-bold text-[var(--accent-cyan)]">{selectedTechnique.id}</span>
              <button onClick={() => setSelectedTechnique(null)} className="text-[var(--text-muted)] hover:text-white text-lg">✕</button>
            </div>

            <h3 className="text-lg font-bold mb-2">{selectedTechnique.name}</h3>
            <p className="text-sm text-[var(--text-secondary)] mb-4">{selectedTechnique.description}</p>

            <div className="space-y-3">
              <div className="p-3 rounded-lg bg-[var(--bg-input)] border border-[var(--border-color)]">
                <label className="text-xs text-[var(--text-muted)] font-mono">TACTIC</label>
                <p className="text-sm font-medium">{selectedTechnique.tactic_name}</p>
              </div>

              <div className="p-3 rounded-lg bg-[var(--bg-input)] border border-[var(--border-color)]">
                <label className="text-xs text-[var(--text-muted)] font-mono">SEVERITY</label>
                <p className={`text-sm font-bold ${
                  selectedTechnique.severity === 'critical' ? 'text-red-400'
                    : selectedTechnique.severity === 'high' ? 'text-orange-400'
                    : selectedTechnique.severity === 'medium' ? 'text-yellow-400'
                    : 'text-blue-400'
                }`}>{selectedTechnique.severity?.toUpperCase()}</p>
              </div>

              {selectedTechnique.sub_techniques && Object.keys(selectedTechnique.sub_techniques).length > 0 && (
                <div>
                  <label className="text-xs text-[var(--text-muted)] font-mono mb-2 block">SUB-TECHNIQUES</label>
                  <div className="space-y-1">
                    {Object.entries(selectedTechnique.sub_techniques).map(([id, name]) => (
                      <div key={id} className="flex items-center gap-2 p-2 rounded bg-[var(--bg-input)] border border-[var(--border-color)]">
                        <span className="text-xs font-mono text-[var(--accent-cyan)]">{id}</span>
                        <span className="text-xs text-[var(--text-secondary)]">{name as string}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
                <label className="text-xs text-cyan-400 font-mono">RECOMMENDED ACTION</label>
                <p className="text-sm text-[var(--text-secondary)] mt-1">{selectedTechnique.recommended_action}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
