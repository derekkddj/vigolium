import { test, expect, seedAuth } from '../fixtures';
import type { Finding } from '../../src/api/types';

// Same distribution as the reported project, with the HIGHs outside page one.
const otherSeverities = [
  ...Array<string>(65).fill('medium'), ...Array<string>(53).fill('low'),
  ...Array<string>(134).fill('info'), ...Array<string>(5).fill('suspect'),
];
const highIDs = new Map([[150, 4540], [240, 1676], [241, 1673]]);
let otherIndex = 0;
const findings = Array.from({ length: 260 }, (_, index) => ({
  id: highIDs.get(index) ?? 10000 + index,
  severity: highIDs.has(index) ? 'high' : otherSeverities[otherIndex++],
  module_name: `Module ${String(index).padStart(3, '0')}`,
  confidence: 'high', matched_at: ['https://example.test/path'],
  found_at: new Date(Date.UTC(2026, 0, 1, 0, 0, 260 - index)).toISOString(),
})) as Finding[];
const rank: Record<string, number> = { info: 0, suspect: 1, low: 2, medium: 3, high: 4, critical: 5 };

for (const theme of ['dark', 'light']) {
  test.describe(`${theme} findings global ordering`, () => {
    test.beforeEach(async ({ page }) => {
      await seedAuth(page);
      await page.addInitScript(theme => localStorage.setItem('vigolium_scheme', `default-${theme}`), theme);
    });

    test('paginates 260 rows, sorts all results before pagination, and preserves the server order and arrows', async ({ page, consoleErrors }) => {
      const queries: URLSearchParams[] = [];
      await page.route('**/api/findings?*', async route => {
        const query = new URL(route.request().url()).searchParams;
        queries.push(query);
        const rows = findings.filter(row => !query.get('severity') || row.severity === query.get('severity'));
        if (query.get('sort') === 'severity') {
          const direction = query.get('order') === 'asc' ? 1 : -1;
          rows.sort((a, b) => ((rank[a.severity] - rank[b.severity]) || (a.id - b.id)) * direction);
        }
        const offset = Number(query.get('offset') || 0);
        await route.fulfill({ json: { items: rows.slice(offset, offset + 100), total: rows.length, offset, limit: 100, has_more: offset + 100 < rows.length } });
      });
      await page.goto('/findings/');
      const pagination = page.getByRole('navigation', { name: 'Findings pagination' });
      const firstID = page.locator('[role="grid"] .ag-row[row-index="0"] [col-id="id"]');
      const severityHeader = page.getByRole('columnheader', { name: /^SEV/ });
      await expect(pagination).toContainText('1–100 of 260 findings');
      await expect(page.getByRole('button', { name: 'Previous', exact: true })).toBeDisabled();
      const next = page.getByRole('button', { name: 'Next', exact: true });
      const buttonBox = await next.boundingBox();
      expect(buttonBox!.height).toBeGreaterThanOrEqual(32);
      expect(buttonBox!.width).toBeGreaterThan(45);
      await next.click();
      await expect(pagination).toContainText('101–200 of 260 findings');
      await next.click();
      await expect(pagination).toContainText('201–260 of 260 findings');
      await expect(next).toBeDisabled();
      expect(queries.some(query => query.get('offset') === '200')).toBe(true);

      await severityHeader.click(); // First click: risk descending, not lexical descending.
      await expect(firstID).toHaveText('4540');
      await expect(page.locator('[role="grid"] .ag-row[row-index="1"] [col-id="id"]')).toHaveText('1676');
      await expect(page.locator('[role="grid"] .ag-row[row-index="2"] [col-id="id"]')).toHaveText('1673');
      await expect(pagination).toContainText('Page 1 of 3');
      expect(queries.at(-1)!.get('sort')).toBe('severity');
      expect(queries.at(-1)!.get('order')).toBe('desc');
      expect(queries.at(-1)!.get('offset')).toBe('0');
      await expect(severityHeader).toHaveAttribute('aria-sort', 'descending');
      await next.click();
      await expect(pagination).toContainText('101–200 of 260 findings');
      expect(queries.at(-1)!.get('sort')).toBe('severity');
      expect(queries.at(-1)!.get('order')).toBe('desc');
      await page.getByRole('button', { name: 'By Host', exact: true }).click();
      await expect(pagination).toContainText('Page 2 of 3');
      await page.getByRole('button', { name: 'Table', exact: true }).click();
      await expect(severityHeader).toHaveAttribute('aria-sort', 'descending');
      await expect(pagination).toContainText('Page 2 of 3');

      await severityHeader.click(); // Ascending: info comes first, HIGHs move to the end globally.
      await expect(page.locator('[role="grid"] .ag-row[row-index="0"] [col-id="severity"]')).toHaveText('info');
      await expect(pagination).toContainText('Page 1 of 3');
      expect(queries.at(-1)!.get('order')).toBe('asc');
      await next.click();
      await expect(pagination).toContainText('Page 2 of 3');
      await next.click();
      await expect(pagination).toContainText('Page 3 of 3');
      await page.locator('[role="grid"]').evaluate(element => { element.scrollTop = element.scrollHeight; });
      await expect(page.locator('[role="grid"] .ag-row[row-index="59"] [col-id="severity"]')).toHaveText('high');
      await severityHeader.click(); // Clear: return to server's default time order, page one.
      await expect(pagination).toContainText('Page 1 of 3');
      await expect(firstID).toHaveText('10000');
      await expect(severityHeader).toHaveAttribute('aria-sort', 'none');
      // Clearing may reuse the fresh default-order page from React Query's cache.
      // Refresh explicitly before asserting the HTTP params, rather than assuming a new GET.
      const refreshed = page.waitForResponse(response => {
        const url = new URL(response.url());
        return url.pathname === '/api/findings' && !url.searchParams.has('sort');
      });
      await page.getByTitle('Refresh', { exact: true }).click();
      await refreshed;
      await expect(pagination).toContainText('1–100 of 260 findings');
      expect(queries.at(-1)!.get('sort')).toBeNull();
      expect(queries.at(-1)!.get('order')).toBeNull();

      await page.getByRole('button', { name: /^sev:all/ }).click();
      await page.getByRole('button', { name: 'high', exact: true }).click();
      await expect(pagination).toContainText('1–3 of 3 findings');
      await expect(page.locator('[role="grid"] .ag-row[role="row"]')).toHaveCount(3);
      expect(queries.at(-1)!.get('severity')).toBe('high');
      expect(queries.at(-1)!.get('offset')).toBe('0');
      expect(consoleErrors.unhandled).toEqual([]);
      expect(consoleErrors.errors).toEqual([]);
    });

    test('hides stale rows and disables page navigation while the globally sorted response is pending', async ({ page, consoleErrors }) => {
      let release: (() => void) | undefined;
      const pending = new Promise<void>(resolve => { release = resolve; });
      const sortedQueries: URLSearchParams[] = [];
      await page.route('**/api/findings?*', async route => {
        const query = new URL(route.request().url()).searchParams;
        const rows = [...findings];
        if (query.get('sort') === 'severity') {
          sortedQueries.push(query);
          await pending;
          rows.sort((a, b) => (rank[b.severity] - rank[a.severity]) || (b.id - a.id));
        }
        const offset = Number(query.get('offset') || 0);
        await route.fulfill({ json: { data: rows.slice(offset, offset + 100), total: rows.length, offset, limit: 100, has_more: offset + 100 < rows.length } });
      });
      await page.goto('/findings/');
      const pagination = page.getByRole('navigation', { name: 'Findings pagination' });
      await expect(pagination).toContainText('Page 1 of 3');
      await page.getByRole('button', { name: 'Next', exact: true }).click();
      await expect(pagination).toContainText('Page 2 of 3');
      await page.getByRole('columnheader', { name: /^SEV/ }).click();
      await expect.poll(() => sortedQueries.length).toBeGreaterThan(0);
      await expect(page.locator('[role="grid"] .ag-row[role="row"]')).toHaveCount(0);
      await expect(pagination).toContainText('Loading findings…');
      await expect(page.getByRole('button', { name: 'Previous', exact: true })).toBeDisabled();
      await expect(page.getByRole('button', { name: 'Next', exact: true })).toBeDisabled();
      expect(sortedQueries.at(-1)!.get('offset')).toBe('0');
      release!();
      await expect(page.locator('[role="grid"] .ag-row[row-index="0"] [col-id="id"]')).toHaveText('4540');
      await expect(pagination).toContainText('1–100 of 260 findings');
      expect(consoleErrors.unhandled).toEqual([]);
      expect(consoleErrors.errors).toEqual([]);
    });
  });
}
