'use client';

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { evidencePalette, type EvidenceTheme } from './HttpMessage';

interface Props {
  findingID: number;
  theme: EvidenceTheme;
  list: ReactNode;
  inspector: ReactNode;
}

/** The list and inspector own separate scroll areas; expanded mode lives outside page scrollers. */
export default function EvidenceWorkspace({ findingID, theme, list, inspector }: Props) {
  const colors = evidencePalette[theme];
  const [expanded, setExpanded] = useState(false);
  const [narrow, setNarrow] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const listPane = useRef<HTMLDivElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  const returnTarget = useRef<string | null>(null);
  const inlineScroll = useRef(0);
  const openDetails = useRef(new Map<string, boolean>());
  const rememberDetails = useCallback(() => {
    for (const details of root.current?.querySelectorAll<HTMLDetailsElement>('details[data-evidence-details]') ?? []) {
      openDetails.current.set(details.getAttribute('data-evidence-details')!, details.open);
    }
  }, []);
  const collapse = useCallback(() => { rememberDetails(); setExpanded(false); }, [rememberDetails]);

  const expand = (opener: HTMLButtonElement) => {
    rememberDetails();
    returnTarget.current = opener.getAttribute('data-evidence-key') ?? 'expand';
    inlineScroll.current = listPane.current?.scrollTop ?? 0;
    setExpanded(true);
  };
  const revealInspector = (opener: HTMLButtonElement) => {
    const width = root.current?.getBoundingClientRect().width ?? 0;
    if (!expanded && (window.matchMedia('(max-width: 899px)').matches || width > 0 && width < 700)) expand(opener);
  };

  useEffect(() => {
    const element = root.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => {
      if (entry) setNarrow(entry.contentRect.width < 700);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, [expanded]);

  useEffect(() => {
    // Portal transitions remount native details: restore them before scroll and focus.
    for (const details of root.current?.querySelectorAll<HTMLDetailsElement>('details[data-evidence-details]') ?? []) {
      details.open = openDetails.current.get(details.getAttribute('data-evidence-details')!) ?? false;
    }
    if (listPane.current) listPane.current.scrollTop = inlineScroll.current;
    if (!expanded) {
      if (returnTarget.current) {
        const target = returnTarget.current === 'expand'
          ? root.current?.querySelector<HTMLButtonElement>('[data-evidence-expand]')
          : Array.from(root.current?.querySelectorAll<HTMLButtonElement>('[data-evidence-key]') ?? [])
            .find((button) => button.getAttribute('data-evidence-key') === returnTarget.current);
        let focusTarget: HTMLElement | undefined = target ?? undefined;
        // Preserve a group folded inside the modal; its hidden button cannot take
        // focus. The outermost closed ancestor's summary remains visible instead.
        for (let parent = target?.parentElement; parent && parent !== root.current; parent = parent.parentElement) {
          if (parent.tagName === 'DETAILS' && !parent.hasAttribute('open')) {
            focusTarget = parent.querySelector<HTMLElement>(':scope > summary') ?? undefined;
          }
        }
        (focusTarget ?? root.current?.querySelector<HTMLButtonElement>('[data-evidence-expand]'))?.focus({ preventScroll: true });
        returnTarget.current = null;
      }
      return;
    }
    const previous = document.body.style.overflow;
    document.body.style.setProperty('overflow', 'hidden');
    closeButton.current?.focus({ preventScroll: true });
    const keyDown = (event: KeyboardEvent) => {
      const dialog = root.current;
      if (!dialog) return;
      if (event.key === 'Escape') {
        event.preventDefault(); event.stopPropagation(); collapse(); return;
      }
      if (event.key !== 'Tab') return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>('button:not(:disabled), summary, [tabindex="0"]'))
        .filter((element) => {
          // A summary can be visible inside its own closed details, but not a closed ancestor.
          for (let parent = element.parentElement; parent && parent !== dialog; parent = parent.parentElement) {
            if (parent.tagName === 'DETAILS' && !parent.hasAttribute('open') && !parent.querySelector(':scope > summary')?.contains(element)) return false;
          }
          return true;
        });
      const first = focusable[0]; const last = focusable.at(-1);
      if (!dialog.contains(document.activeElement) || (event.shiftKey ? document.activeElement === first : document.activeElement === last)) {
        event.preventDefault(); event.stopPropagation(); (event.shiftKey ? last : first)?.focus();
      }
    };
    document.addEventListener('keydown', keyDown, true);
    return () => {
      document.body.style.setProperty('overflow', previous);
      document.removeEventListener('keydown', keyDown, true);
    };
  }, [expanded, collapse]);

  const content = <div ref={root} role={expanded ? 'dialog' : undefined} aria-label={expanded ? 'Finding evidence workspace' : undefined}
    aria-modal={expanded ? true : undefined}
    className={expanded ? 'fixed inset-0 z-[60] flex flex-col text-xs' : 'border min-w-0'}
    style={{ borderColor: colors.border, background: colors.background, color: colors.text }}>
    {expanded && <header className="shrink-0 flex items-center gap-3 border-b p-3" style={{ borderColor: colors.border }}>
      <h3 className="flex-1 min-w-0 font-semibold">Finding #{findingID} · evidence</h3>
      <button ref={closeButton} className="border px-3 py-2" style={{ borderColor: colors.border, color: colors.accent }} aria-label="Close evidence workspace" onClick={collapse}>Close</button>
    </header>}
    <div className="grid min-h-0 min-w-0 gap-0" style={{
      height: expanded ? undefined : 'min(65vh, 640px)', flex: expanded ? 1 : undefined,
      gridTemplateColumns: narrow ? 'minmax(0, 1fr)' : 'minmax(220px, 0.85fr) minmax(0, 1.15fr)',
      gridTemplateRows: narrow ? 'minmax(0, 160px) minmax(0, 1fr)' : 'minmax(0, 1fr)',
    }}>
      <div ref={listPane} role="region" aria-label="Evidence list" tabIndex={0} onClick={(event) => {
        const opener = event.target instanceof Element ? event.target.closest<HTMLButtonElement>('button[data-evidence-key]') : null;
        if (opener && !opener.disabled) revealInspector(opener);
      }}
        className="min-h-0 min-w-0 overflow-y-auto overscroll-contain p-2 space-y-2 border-r" style={{ borderColor: colors.border }}>
        {list}
      </div>
      <aside aria-label="Evidence inspector" className="min-h-0 min-w-0 flex flex-col">
        {!expanded && <div className="shrink-0 border-b p-2" style={{ borderColor: colors.border }}>
          <button data-evidence-expand className="border px-2 py-1" style={{ borderColor: colors.border, color: colors.accent }} onClick={(event) => expand(event.currentTarget)}>Expand evidence workspace</button>
        </div>}
        {inspector}
      </aside>
    </div>
  </div>;
  return expanded ? createPortal(content, document.body) : content;
}
