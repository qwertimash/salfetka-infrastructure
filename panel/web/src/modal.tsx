import { useEffect, useId, useRef } from 'react'
import type { ReactNode } from 'react'
import { createPortal } from 'react-dom'

export function Modal({ title, children, close }: { title: string; children: ReactNode; close: () => void }) {
  const ref = useRef<HTMLDivElement>(null), titleID = useId(), onClose = useRef(close)
  onClose.current = close
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    ref.current?.focus()
    const key = (e: KeyboardEvent) => {
      if (Array.from(document.querySelectorAll('[role=dialog]')).at(-1) !== ref.current) return
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); onClose.current() }
      if (e.key !== 'Tab') return
      const nodes = Array.from(ref.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]') ?? []).filter(n => !n.hidden)
      const first = nodes[0], last = nodes.at(-1)
      if (!first) { e.preventDefault(); return }
      if (e.shiftKey && (document.activeElement === first || document.activeElement === ref.current)) { e.preventDefault(); last?.focus() }
      else if (!e.shiftKey && (document.activeElement === last || document.activeElement === ref.current)) { e.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', key, true)
    return () => { document.removeEventListener('keydown', key, true); document.body.style.overflow = overflow; previous?.focus() }
  }, [])
  return createPortal(<div className="modal-backdrop"><div ref={ref} role="dialog" aria-modal="true" aria-labelledby={titleID} tabIndex={-1} className="panel-modal"><header><h2 id={titleID}>{title}</h2><button className="button secondary small" aria-label="Закрыть окно" onClick={close}>✕</button></header>{children}</div></div>, document.body)
}
