import { Reveal, SectionHeader, Badge } from '../lib/ui.jsx'

const FRAMEWORKS = [
  ['NIS2', 'Network and Information Security Directive', "Exposed endpoints, missing authentication, and data-exposure findings map to NIS2's risk-management and incident-handling obligations."],
  ['ISO 27001', 'Information Security Management', 'Discovery and posture scoring line up with Annex A controls for access, logging, and secure operations.'],
]

export default function Compliance() {
  return (
    <section id="compliance" className="border-t border-line py-16 md:py-20">
      <Reveal>
        <SectionHeader
          title="The same signal that protects your APIs feeds the paperwork."
          sub="Every finding AEGIS raises ties to the controls a European security audit checks against."
        />
      </Reveal>
      <div className="mt-10 divide-y divide-line border-t border-line">
        {FRAMEWORKS.map(([tag, name, body], i) => (
          <Reveal key={tag} delay={i * 0.06}>
            <div className="grid grid-cols-1 gap-3 py-7 sm:grid-cols-[140px_1fr] sm:gap-8">
              <div><Badge tone="accent">{tag}</Badge></div>
              <div>
                <h3 className="text-[16px] font-medium text-ink">{name}</h3>
                <p className="mt-2 max-w-xl text-[14.5px] leading-relaxed text-muted">{body}</p>
              </div>
            </div>
          </Reveal>
        ))}
      </div>
    </section>
  )
}
