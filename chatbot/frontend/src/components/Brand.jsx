export function VedappuMark({ size = 38, className = '' }) {
  return (
    <span className={'brand-mark ' + className} style={{ width: size, height: size }} aria-hidden="true">
      <svg viewBox="0 0 48 48" fill="none">
        <path d="M11 14.5 21 34l5.7-10.9L33 14.5" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
        <path d="m28.5 30 4.5 4.5 4.5-4.5" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="36" cy="13" r="2" fill="currentColor" />
      </svg>
    </span>
  )
}

export default function Brand({ compact = false }) {
  return (
    <div className="flex items-center gap-3">
      <VedappuMark size={compact ? 34 : 40} />
      <div className="flex flex-col leading-tight">
        <span className={'font-semibold tracking-[-.04em] text-[var(--text)] ' + (compact ? 'text-[17px]' : 'text-[19px]')}>Vedappu</span>
        {!compact && <span className="mt-0.5 text-[9px] font-bold tracking-[.2em] text-[var(--accent)]">PRIVATE AI</span>}
      </div>
    </div>
  )
}
