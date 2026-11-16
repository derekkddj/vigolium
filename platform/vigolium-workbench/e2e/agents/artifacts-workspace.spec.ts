import { test, expect, seedAuth, FIXTURE_PROJECT, FIXTURE_API_KEY } from '../fixtures';
import type { Page } from '@playwright/test';

const RUN_UUID = '4769c042-e880-44e2-b221-4d1d33d8760a';
const FILE = 'auth-config.yaml';
const TEXT = 'tool: fixture evidence\n'.repeat(9500); // ~200 KiB, enough to exercise real scrolling.
const SESSION = {
  uuid: RUN_UUID, status: 'completed', mode: 'autopilot', agent_name: 'olium',
  target_url: 'https://example.invalid', finding_count: 0, record_count: 0, saved_count: 0,
  duration_ms: 1697000, started_at: '2026-11-12T17:27:00Z', completed_at: '2026-11-12T17:56:00Z',
  created_at: '2026-11-12T17:27:00Z',
};
const FILES = Array.from({ length: 30 }, (_, index) => ({ name: index === 0 ? FILE : `evidence-${index}.txt`, kind: index === 0 ? 'yaml' : 'text', size: Buffer.byteLength(TEXT) }));

async function mockRun(page: Page) {
  await page.route('**/api/agent/sessions*', route => route.fulfill({ json: { data: [SESSION], total: 1, has_more: false } }));
  await page.route(`**/api/agent/sessions/${RUN_UUID}`, route => route.fulfill({ json: SESSION }));
  // These routes are deliberately separate from sessions*: that glob does not match nested paths.
  await page.route(`**/api/agent/sessions/${RUN_UUID}/artifacts`, route => {
    expect(route.request().headers()['x-project-uuid']).toBe(FIXTURE_PROJECT.uuid);
    expect(route.request().headers().authorization).toBe(`Bearer ${FIXTURE_API_KEY}`);
    return route.fulfill({ json: { artifacts: FILES, truncated: false } });
  });
  await page.route(`**/api/agent/sessions/${RUN_UUID}/artifacts/**`, route => {
    expect(route.request().headers()['x-project-uuid']).toBe(FIXTURE_PROJECT.uuid);
    expect(route.request().headers().authorization).toBe(`Bearer ${FIXTURE_API_KEY}`);
    return route.fulfill({
      contentType: 'text/plain', body: TEXT,
      headers: { 'X-Artifact-Total-Size': String(Buffer.byteLength(TEXT)), 'X-Artifact-Offset': '0', 'X-Artifact-Returned-Bytes': String(Buffer.byteLength(TEXT)), 'X-Artifact-Truncated': '0' },
    });
  });
}

/** Real scroll owners, not just overflow classes on naturally sized elements. */
async function scrollAncestors(locator: import('@playwright/test').Locator) {
  return locator.evaluate(el => {
    const owners: string[] = [];
    for (let parent = el.parentElement; parent; parent = parent.parentElement) {
      if (/^(auto|scroll)$/.test(getComputedStyle(parent).overflowY) && parent.scrollHeight > parent.clientHeight) owners.push(parent.className);
    }
    return owners;
  });
}

for (const theme of ['dark', 'light'] as const) {
  test.describe(`${theme} run artifact workspace`, () => {
    test.use({ viewport: { width: 1440, height: 760 } });
    test.beforeEach(async ({ page }) => {
      await seedAuth(page);
      await page.addInitScript(scheme => {
        localStorage.setItem('vigolium_scheme', scheme);
        // Match production HTTP capabilities: exercise the bounded Blob download,
        // not localhost's native File System Access picker.
        Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: undefined });
      }, `default-${theme}`);
      await mockRun(page);
    });

    test('uses the viewport for evidence, keeps scrolls separate and preserves browser history', async ({ page, consoleErrors }) => {
      await page.goto(`/agentic-scan/?session=${RUN_UUID}`);
      const detail = page.getByText('SESSION DETAILS', { exact: true });
      await expect(detail).toBeVisible();
      expect((await scrollAncestors(detail)).length).toBeLessThanOrEqual(1);
      expect((await scrollAncestors(page.getByRole('region', { name: 'Run artifacts', exact: true }))).length).toBeLessThanOrEqual(1);
      const table = page.getByRole('columnheader', { name: 'DURATION' }).locator('xpath=ancestor::table');
      const width = await table.evaluate(el => ({ scroll: el.parentElement!.scrollWidth, client: el.parentElement!.clientWidth }));
      expect(width.scroll).toBeLessThanOrEqual(width.client);
      const durationBox = await page.getByRole('columnheader', { name: 'DURATION' }).boundingBox();
      expect(durationBox!.x + durationBox!.width).toBeLessThanOrEqual(1440);
      await expect(page.getByRole('table', { name: 'Artifact files' }).getByRole('button')).toHaveCount(12);
      await page.getByRole('button', { name: FILE, exact: true }).click();
      const dialog = page.getByRole('dialog', { name: 'Run artifacts workspace' });
      await expect(dialog).toBeVisible();
      await expect(dialog).toHaveCSS('background-color', theme === 'dark' ? 'rgb(20, 19, 16)' : 'rgb(237, 228, 209)');
      const content = dialog.getByLabel('Artifact content');
      await expect(content).toContainText('tool: fixture evidence');
      const box = await content.boundingBox();
      expect(box!.height).toBeGreaterThanOrEqual(760 * 0.6);
      expect(await scrollAncestors(content)).toEqual([]);
      const sidebar = dialog.getByRole('navigation', { name: 'Workspace artifact files' });
      expect(await scrollAncestors(sidebar)).toEqual([]);
      expect(await page.evaluate(() => document.body.style.overflow)).toBe('hidden');
      await content.evaluate(el => { el.scrollTop = 600; });
      expect(await content.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
      await sidebar.getByRole('searchbox').fill('EVIDENCE-29');
      await expect(sidebar.getByRole('button')).toHaveCount(1);
      await expect(page).toHaveURL(new RegExp(`session=${RUN_UUID}.*artifact=auth-config.yaml`));
      const downloadEvent = page.waitForEvent('download');
      await dialog.getByRole('button', { name: 'Download exact bytes' }).click();
      const download = await downloadEvent;
      expect(await download.failure()).toBeNull();
      await expect(dialog.getByRole('status')).toContainText('Complete response verified:');
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveCount(0);
      await expect(page.getByRole('button', { name: FILE, exact: true })).toBeFocused();
      await page.getByRole('button', { name: FILE, exact: true }).click();
      await expect(dialog.getByLabel('Artifact content')).toContainText('tool: fixture evidence');
      await page.goBack();
      await expect(dialog).toHaveCount(0);
      await expect(page).toHaveURL(new RegExp(`session=${RUN_UUID}$`));
      expect(await page.evaluate(() => document.body.style.overflow)).not.toBe('hidden');
      await expect(page.getByRole('button', { name: FILE, exact: true })).toBeFocused();
      await page.getByRole('button', { name: FILE, exact: true }).click();
      await page.reload();
      await expect(page.getByRole('dialog').getByLabel('Artifact content')).toContainText('tool: fixture evidence');
      await expect(page.getByRole('dialog').getByRole('heading', { name: FILE, exact: true })).toBeVisible();
      await page.getByRole('button', { name: 'Close artifacts workspace' }).click();
      await expect(page).toHaveURL(new RegExp(`session=${RUN_UUID}$`));
      expect(consoleErrors.errors).toEqual([]);
      expect(consoleErrors.unhandled).toEqual([]);
    });
  });
}
