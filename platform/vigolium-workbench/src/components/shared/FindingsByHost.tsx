'use client';

import { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { useFindingHosts, useFindings } from '@/api/hooks';
import type { Finding, FindingHostCount, FindingsQueryParams } from '@/api/types';
import FindingsPagination from '@/components/shared/FindingsPagination';
import { formatDate } from '@/lib/formatters';
import { CONFIDENCE_COLORS, SEVERITY_COLORS } from '@/lib/domainPalette';

const HOST_FINDINGS_PAGE_SIZE = 100;

type Theme = 'dark' | 'light';

function HostFindingGroup({
  host,
  filters,
  theme,
  onSelectFinding,
  selectedFindingId,
}: {
  host: FindingHostCount;
  filters: FindingsQueryParams;
  theme: Theme;
  onSelectFinding: (id: number) => void;
  selectedFindingId: number | null;
}) {
  const [expanded, setExpanded] = useState(false);
  const [offset, setOffset] = useState(0);
  const query = useFindings({
    ...filters,
    domain: host.hostname,
    limit: HOST_FINDINGS_PAGE_SIZE,
    offset,
  }, { enabled: expanded, preservePreviousData: false });
  const rows = query.isPlaceholderData ? [] : query.data?.data ?? [];
  const dark = theme === 'dark';
  const muted = dark ? '#918175' : '#708e8e';
  const border = dark ? '#2e2b26' : '#bbc3c4';
  const hostColor = dark ? '#68a8e4' : '#0078c8';

  return (
    <section>
      <button
        type="button"
        aria-expanded={expanded}
        onClick={() => setExpanded((value) => !value)}
        className={`w-full flex items-center gap-1.5 px-3 py-1.5 border-b hover:opacity-90 text-left ${dark ? 'hover:bg-[#272520]' : 'hover:bg-[#ede4d1]'}`}
        style={{ borderColor: border }}
      >
        {expanded ? <ChevronDown className="w-3 h-3 shrink-0" style={{ color: muted }} /> : <ChevronRight className="w-3 h-3 shrink-0" style={{ color: muted }} />}
        <span className="text-xs font-bold truncate" style={{ color: hostColor }}>{host.hostname}</span>
        <span className="text-xs ml-auto shrink-0" style={{ color: muted }}>{host.total}</span>
      </button>
      {expanded && (
        <div>
          {query.isError && <p role="alert" className="px-3 py-2 text-xs" style={{ color: hostColor }}>Could not load findings for {host.hostname}.</p>}
          {(query.isLoading || query.isPlaceholderData) && <p className="px-3 py-2 text-xs" style={{ color: muted }}>Loading findings…</p>}
          {!query.isLoading && !query.isPlaceholderData && rows.map((finding) => (
            <HostFindingRow
              key={finding.id}
              finding={finding}
              theme={theme}
              selected={selectedFindingId === finding.id}
              onClick={() => onSelectFinding(finding.id)}
            />
          ))}
          {query.data && !query.isPlaceholderData && (
            <FindingsPagination
              ariaLabel={`Findings pagination for ${host.hostname}`}
              offset={query.data.offset}
              pageSize={query.data.limit || HOST_FINDINGS_PAGE_SIZE}
              returned={rows.length}
              total={query.data.total}
              hasMore={query.data.has_more}
              busy={query.isFetching}
              onPageChange={(page) => setOffset((page - 1) * HOST_FINDINGS_PAGE_SIZE)}
            />
          )}
        </div>
      )}
    </section>
  );
}

function HostFindingRow({
  finding,
  theme,
  selected,
  onClick,
}: {
  finding: Finding;
  theme: Theme;
  selected: boolean;
  onClick: () => void;
}) {
  const dark = theme === 'dark';
  const muted = dark ? '#918175' : '#708e8e';
  const border = dark ? '#2e2b26' : '#bbc3c4';
  return (
    <button
      type="button"
      data-testid="host-finding-row"
      onClick={onClick}
      className={`w-full flex items-center gap-2 px-3 pl-7 py-1 border-b text-left text-xs hover:opacity-90 ${dark ? 'hover:bg-[#272520]' : 'hover:bg-[#ede4d1]'} ${selected ? (dark ? 'bg-[#272520]' : 'bg-[#ede4d1]') : ''}`}
      style={{ borderColor: border }}
    >
      <span className="font-bold w-16 shrink-0 uppercase" style={{ color: SEVERITY_COLORS[finding.severity] || muted }}>{finding.severity}</span>
      <span className="w-16 shrink-0" style={{ color: CONFIDENCE_COLORS[finding.confidence] || muted }}>{finding.confidence}</span>
      <span className="w-40 shrink-0 truncate" style={{ color: muted }}>{finding.module_name}</span>
      <span className="truncate flex-1 min-w-0" style={{ color: dark ? '#fce8c3' : '#005661' }}>{finding.description || '—'}</span>
      <span className="w-52 shrink-0 text-right truncate" style={{ color: muted }}>{finding.matched_at?.join(', ') || '—'}</span>
      <span className="w-28 shrink-0 text-right" style={{ color: muted }}>{finding.found_at ? formatDate(finding.found_at) : '—'}</span>
    </button>
  );
}

export default function FindingsByHost({
  filters,
  theme,
  onSelectFinding,
  selectedFindingId,
}: {
  filters: FindingsQueryParams;
  theme: Theme;
  onSelectFinding: (id: number) => void;
  selectedFindingId: number | null;
}) {
  // Aggregates are independent of the table's current page and sort order.
  const aggregateFilters = useMemo<FindingsQueryParams>(() => ({
    severity: filters.severity,
    search: filters.search,
    domain: filters.domain,
    module_name: filters.module_name,
    module_type: filters.module_type,
    finding_source: filters.finding_source,
    status: filters.status,
    scan_uuid: filters.scan_uuid,
  }), [filters.severity, filters.search, filters.domain, filters.module_name, filters.module_type, filters.finding_source, filters.status, filters.scan_uuid]);
  const hostsQuery = useFindingHosts(aggregateFilters);
  const hosts = hostsQuery.data?.data ?? [];
  const dark = theme === 'dark';
  const muted = dark ? '#918175' : '#708e8e';
  const border = dark ? '#2e2b26' : '#bbc3c4';
  const header = dark ? '#1c1b19' : '#f6edda';

  if (hostsQuery.isLoading) return <div className="p-3 text-xs" style={{ color: muted }}>Loading hosts…</div>;
  if (hostsQuery.isError) return <div role="alert" className="p-3 text-xs" style={{ color: muted }}>Could not load finding hosts.</div>;

  return (
    <div className="overflow-y-auto flex-1">
      <div className="flex items-center gap-2 px-3 pl-7 py-1 border-b text-xs font-bold sticky top-0 z-10" style={{ borderColor: border, color: muted, background: header }}>
        <span className="w-16 shrink-0">SEV</span>
        <span className="w-16 shrink-0">CONF</span>
        <span className="w-40 shrink-0">MODULE</span>
        <span className="flex-1">DESCRIPTION</span>
        <span className="w-52 shrink-0 text-right">MATCHED_AT</span>
        <span className="w-28 shrink-0 text-right">TIME</span>
      </div>
      {hosts.map((host) => (
        <HostFindingGroup
          key={`${host.hostname}:${JSON.stringify(aggregateFilters)}`}
          host={host}
          filters={aggregateFilters}
          theme={theme}
          onSelectFinding={onSelectFinding}
          selectedFindingId={selectedFindingId}
        />
      ))}
      {hosts.length === 0 && <div className="p-3 text-xs text-center" style={{ color: muted }}>no findings</div>}
    </div>
  );
}
