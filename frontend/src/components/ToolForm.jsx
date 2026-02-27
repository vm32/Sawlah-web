import { Play, Square, Loader2 } from "lucide-react";

export function FormField({ label, children, hint }) {
  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-semibold uppercase tracking-wider text-sawlah-muted">{label}</label>
      {children}
      {hint && <p className="text-[11px] text-sawlah-dim">{hint}</p>}
    </div>
  );
}

export function TextInput({ value, onChange, placeholder, ...props }) {
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full"
      {...props}
    />
  );
}

export function SelectInput({ value, onChange, options }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} className="w-full">
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  );
}

export function CheckboxInput({ checked, onChange, label }) {
  return (
    <label className="flex items-center gap-2 cursor-pointer group">
      <div
        className={`w-4 h-4 rounded border-2 flex items-center justify-center transition-all ${
          checked ? "bg-sawlah-red border-sawlah-red" : "border-sawlah-border group-hover:border-sawlah-muted"
        }`}
        onClick={() => onChange(!checked)}
      >
        {checked && (
          <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        )}
      </div>
      <span className="text-sm text-sawlah-muted group-hover:text-sawlah-text transition-colors">{label}</span>
    </label>
  );
}

export function RunButton({ onClick, running, onStop }) {
  if (running) {
    return (
      <button
        onClick={onStop}
        className="flex items-center gap-2 px-6 py-2.5 bg-sawlah-red-hover text-white rounded-lg font-semibold text-sm hover:bg-red-800 transition-colors"
      >
        <Square className="w-4 h-4" />
        Stop
      </button>
    );
  }
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2 px-6 py-2.5 bg-sawlah-red text-white rounded-lg font-semibold text-sm hover:bg-sawlah-red-hover transition-colors shadow-lg shadow-sawlah-red-glow"
    >
      <Play className="w-4 h-4" />
      Run
    </button>
  );
}

export function CommandPreview({ command }) {
  if (!command) return null;
  return (
    <div className="bg-black/50 border border-sawlah-border rounded-lg p-3 font-mono text-xs text-sawlah-green break-all">
      <span className="text-sawlah-red">$</span> {command}
    </div>
  );
}

export function PageHeader({ title, description, icon: Icon }) {
  return (
    <div className="mb-6">
      <div className="flex items-center gap-3 mb-1">
        {Icon && <Icon className="w-6 h-6 text-sawlah-red" />}
        <h1 className="text-2xl font-bold text-sawlah-text">{title}</h1>
      </div>
      {description && <p className="text-sm text-sawlah-muted ml-9">{description}</p>}
    </div>
  );
}
