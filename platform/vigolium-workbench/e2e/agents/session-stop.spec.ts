import { test, expect, seedAuth, FIXTURE_PROJECT, FIXTURE_API_KEY } from '../fixtures';
import type { Locator, Route } from '@playwright/test';

const RUN_UUID = '4769c042-e880-44e2-b221-4d1d33d8760a';
const OTHER_UUID = '19b646d6-6f07-4561-8f49-6bfa1145655b';
const FINISHED_UUID = '24b75572-c2de-4c8b-a999-d376c7316407';
const SESSION = {
  uuid: RUN_UUID, status: 'running', mode: 'autopilot', agent_name: 'olium',
  target_url: 'https://example.invalid', finding_count: 0, record_count: 0, saved_count: 0,
  duration_ms: 60000, started_at: '2026-11-13T12:00:00Z', created_at: '2026-11-13T12:00:00Z',
};

async function textContrast(button: Locator) {
  return button.evaluate(element => {
    // Canvas normalizes modern CSS color()/color-mix() as well as rgb().
    const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1;
    const context = canvas.getContext('2d')!;
    const rgb = (value: string) => {
      context.clearRect(0, 0, 1, 1); context.fillStyle = value; context.fillRect(0, 0, 1, 1);
      const pixel = context.getImageData(0, 0, 1, 1).data;
      return [pixel[0], pixel[1], pixel[2], pixel[3] / 255];
    };
    const chain: Element[] = [];
    for (let current: Element | null = element; current; current = current.parentElement) chain.push(current);
    let background = [255, 255, 255];
    for (const layer of chain.reverse()) {
      const color = rgb(getComputedStyle(layer).backgroundColor);
      const alpha = color[3] ?? 1;
      background = background.map((channel, i) => color[i] * alpha + channel * (1 - alpha));
    }
    const luminance = (color: number[]) => color.slice(0, 3).map(channel => {
      const value = channel / 255;
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
    }).reduce((sum, channel, i) => sum + channel * [0.2126, 0.7152, 0.0722][i], 0);
    const foreground = luminance(rgb(getComputedStyle(element).color));
    const backdrop = luminance(background);
    return (Math.max(foreground, backdrop) + 0.05) / (Math.min(foreground, backdrop) + 0.05);
  });
}

function assertCancellation(route: Route) {
  expect(route.request().method()).toBe('POST');
  expect(route.request().headers()['x-project-uuid']).toBe(FIXTURE_PROJECT.uuid);
  expect(route.request().headers().authorization).toBe(`Bearer ${FIXTURE_API_KEY}`);
}

for (const theme of ['dark', 'light'] as const) {
  test.describe(`${theme} session STOP`, () => {
    test.use({ viewport: { width: 1440, height: 760 } });
    test.beforeEach(async ({ page }) => {
      await seedAuth(page);
      await page.addInitScript(scheme => localStorage.setItem('vigolium_scheme', scheme), `default-${theme}`);
    });

    test('stops an externally started run after reload and immediately refreshes session history', async ({ page, consoleErrors }) => {
      let status = 'running';
      let historyReads = 0;
      const posts: string[] = [];
      await page.route('**/api/agent/sessions*', route => {
        historyReads++;
        return route.fulfill({ json: { data: [{ ...SESSION, status }, { ...SESSION, uuid: FINISHED_UUID, status: 'completed' }], total: 2, has_more: false } });
      });
      await page.route('**/api/agent/scans/*/cancel', route => {
        assertCancellation(route);
        posts.push(new URL(route.request().url()).pathname);
        status = 'cancelled';
        return route.fulfill({ json: { status: 'cancelling' } });
      });
      await page.goto('/agentic-scan/');
      const stop = page.getByRole('button', { name: `Stop run ${RUN_UUID}`, exact: true });
      await expect(stop).toBeVisible();
      await page.reload();
      await expect(stop).toBeVisible();
      // No locally followed run exists: the form still offers START SCAN.
      await expect(page.getByRole('button', { name: 'START SCAN', exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: `Stop run ${FINISHED_UUID}` })).toHaveCount(0);
      const table = page.getByRole('columnheader', { name: 'ACTIONS' }).locator('xpath=ancestor::table');
      const width = await table.evaluate(el => ({ scroll: el.parentElement!.scrollWidth, client: el.parentElement!.clientWidth }));
      expect(width.scroll).toBeLessThanOrEqual(width.client);
      expect(await textContrast(stop)).toBeGreaterThanOrEqual(4.5);
      await stop.hover();
      await expect.poll(() => textContrast(stop)).toBeGreaterThanOrEqual(4.5);
      const readsBefore = historyReads;
      await stop.click();
      // Five-second expectation: a successful POST invalidates the list, rather
      // than waiting for the existing 30-second polling interval.
      await expect(stop).toHaveCount(0);
      await expect(page.getByText(RUN_UUID.slice(0, 8), { exact: true }).locator('xpath=ancestor::tr')).toContainText('cancelled');
      expect(historyReads).toBeGreaterThan(readsBefore);
      expect(posts).toEqual([`/api/agent/scans/${RUN_UUID}/cancel`]);
      expect(new URL(page.url()).search).toBe('');
      await expect(page.getByText('SESSION DETAILS', { exact: true })).toHaveCount(0);
      expect(consoleErrors.errors).toEqual([]);
      expect(consoleErrors.unhandled).toEqual([]);
    });

    test('settles concurrent STOPs independently, deduplicates clicks and shows a contextual 404 with retry', async ({ page, consoleErrors }) => {
      let otherStatus = 'running';
      let retry = false;
      const posts: string[] = [];
      const held = new Map<string, () => void>();
      await page.route('**/api/agent/sessions*', route => route.fulfill({ json: {
        data: [SESSION, { ...SESSION, uuid: OTHER_UUID, status: otherStatus }], total: 2, has_more: false,
      } }));
      await page.route('**/api/agent/scans/*/cancel', async route => {
        assertCancellation(route);
        const uuid = new URL(route.request().url()).pathname.split('/').at(-2)!;
        posts.push(uuid);
        if (!retry) await new Promise<void>(resolve => { held.set(uuid, resolve); });
        if (uuid === RUN_UUID && !retry) {
          await route.fulfill({ status: 404, json: { error: 'run not found or already finished' } });
        } else {
          if (uuid === OTHER_UUID) otherStatus = 'cancelled';
          await route.fulfill({ json: { status: 'cancelling' } });
        }
      });
      await page.goto('/agentic-scan/');
      const first = page.getByRole('button', { name: `Stop run ${RUN_UUID}`, exact: true });
      const second = page.getByRole('button', { name: `Stop run ${OTHER_UUID}`, exact: true });
      await expect(first).toBeVisible();
      // Same-turn clicks exercise the synchronous UUID guard, not just disabled.
      await first.evaluate(button => { (button as HTMLButtonElement).click(); (button as HTMLButtonElement).click(); });
      await expect(first).toBeDisabled();
      await expect(first).toHaveText('STOPPING…');
      await expect(second).toBeEnabled();
      await second.click();
      await expect(second).toBeDisabled();
      await expect.poll(() => held.size).toBe(2);
      expect(posts).toEqual([RUN_UUID, OTHER_UUID]);
      held.get(RUN_UUID)!();
      const error = page.getByRole('columnheader', { name: 'ACTIONS' }).locator('xpath=ancestor::table').getByRole('alert');
      await expect(error).toContainText(RUN_UUID);
      await expect(error).toContainText('run not found or already finished');
      await expect(error).toContainText('may no longer track this run');
      await expect(error).toHaveCount(1);
      await expect(first).toBeEnabled();
      await expect(second).toBeDisabled();
      held.get(OTHER_UUID)!();
      await expect(second).toHaveCount(0);
      await expect(error).toBeVisible(); // The other row's success does not erase it.
      retry = true;
      await first.click();
      await expect(error).toHaveCount(0);
      await expect(first).toBeEnabled();
      expect(posts).toEqual([RUN_UUID, OTHER_UUID, RUN_UUID]);
      expect(new URL(page.url()).search).toBe('');
      await expect(page.getByText('SESSION DETAILS', { exact: true })).toHaveCount(0);
      expect(consoleErrors.errors).toEqual([]);
      expect(consoleErrors.unhandled).toEqual([]);
    });
  });
}
