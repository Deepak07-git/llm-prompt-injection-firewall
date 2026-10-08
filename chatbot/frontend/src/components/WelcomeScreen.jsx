import { ArrowRight, Braces, FileSearch, Lightbulb, MessageCircle } from 'lucide-react'
import { VedappuMark } from './Brand.jsx'
import SuggestionCard from './SuggestionCard.jsx'

const suggestions = [
  { icon: Lightbulb, title: 'Explain a cybersecurity concept', detail: 'Learn clearly, one idea at a time', prompt: 'Explain prompt injection in plain language, with a safe example and practical defenses.' },
  { icon: FileSearch, title: 'Analyze this log', detail: 'Spot patterns in text you share', prompt: 'Help me analyze a security log. First, tell me what details to paste and what to redact.' },
  { icon: Braces, title: 'Help me write Python code', detail: 'Build and understand a small script', prompt: 'Help me write a Python script. Ask what I want it to do, then explain the code as we build it.' },
  { icon: MessageCircle, title: 'Ask Vedappu anything', detail: 'Start with whatever is on your mind', prompt: 'Hi Vedappu. What kinds of things can you help me with?' },
]

export default function WelcomeScreen({ onSelect }) {
  return (
    <div className="mx-auto flex min-h-full w-full max-w-[840px] flex-col justify-start px-4 py-10 sm:px-6 lg:justify-center">
      <div className="mb-7 flex justify-center"><VedappuMark size={66} className="hero-mark" /></div>
      <p className="mb-3 text-center text-[10px] font-bold uppercase tracking-[.24em] text-[var(--accent)]">Your space to think</p>
      <h1 className="text-center text-[clamp(32px,4.5vw,52px)] font-semibold leading-[1.08] tracking-[-.055em] text-[var(--text)]">Welcome to <span className="text-[var(--accent)]">Vedappu</span></h1>
      <p className="mx-auto mt-4 max-w-[490px] text-center text-[14px] leading-6 text-[var(--muted)]">Your private AI assistant, running locally.</p>
      <div className="mt-10 grid grid-cols-1 gap-3 sm:grid-cols-2">
        {suggestions.map(item => <SuggestionCard key={item.title} {...item} onSelect={onSelect} />)}
      </div>
      <p className="mt-8 flex items-center justify-center gap-2 text-center text-[11px] text-[var(--muted)]">
        Try a suggestion or write your own message <ArrowRight size={13} />
      </p>
    </div>
  )
}
