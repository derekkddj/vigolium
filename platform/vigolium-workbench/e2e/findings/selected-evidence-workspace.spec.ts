import { test, expect, seedAuth, FIXTURE_PROJECT, FIXTURE_API_KEY } from '../fixtures';
import type { Locator, Page, Route } from '@playwright/test';
import type { EvidenceEntry, EvidenceExchange, Finding, FindingOccurrence } from '../../src/api/types';

// Public, synthetic analogue of finding 19928: one scan, separate GET and POST
// detections, each with its own primary declaration. The manifest has no methods
// or bytes; only the exact selected receipt can tell us what was sent.
const FINDING_ID = 19928;
const SCAN_UUID = '51111111-1111-4111-8111-111111111111';
const FINDING_URL = 'https://example.test/reports/selected-evidence?fixture=public';
const GET_OCCURRENCE = '62222222-2222-4222-8222-222222222201';
const POST_OCCURRENCE = '62222222-2222-4222-8222-222222222202';

function occurrence(occurrenceID: string, sequence: number): FindingOccurrence {
  const entry = (index: number, role: EvidenceEntry['role'], primary = false): EvidenceEntry => ({
    exchange_id: `73333333-3333-4333-8333-${String(sequence * 100 + index).padStart(12, '0')}`,
    role, primary, occurrence_id: occurrenceID, scan_uuid: SCAN_UUID,
    finding_url: FINDING_URL,
    label: primary ? 'Synthetic main selection (producer declaration)' : `Synthetic ${role} capture ${index}`,
  });
  return {
    occurrence_id: occurrenceID, scan_uuid: SCAN_UUID, evidence_status: 'selected',
    entries: [
      entry(0, 'attack', true),
      ...Array.from({ length: 12 }, (_, index) => entry(index + 1, 'control')),
      ...Array.from({ length: 12 }, (_, index) => entry(index + 13, 'baseline')),
    ],
  };
}

const GET_DETECTION = occurrence(GET_OCCURRENCE, 1);
const POST_DETECTION = occurrence(POST_OCCURRENCE, 2);
const GET_PRIMARY = GET_DETECTION.entries[0];
const POST_PRIMARY = POST_DETECTION.entries[0];
const FINDING: Finding = {
  id: FINDING_ID, project_uuid: FIXTURE_PROJECT.uuid, url: FINDING_URL, hostname: 'example.test',
  scan_uuid: SCAN_UUID, http_record_uuids: [], module_id: 'synthetic-evidence',
  module_name: 'Synthetic selected evidence fixture', module_type: 'active',
  finding_source: 'native', finding_hash: 'public-playwright-selected-evidence',
  severity: 'medium', confidence: 'tentative', status: 'draft', evidence_status: 'selected',
  found_at: '2026-11-01T12:01:00Z', created_at: '2026-11-01T12:00:00Z',
  occurrences: [GET_DETECTION, POST_DETECTION],
  evidence: [...GET_DETECTION.entries, ...POST_DETECTION.entries],
};

function responseBytes(exchangeID: string): Buffer {
  return Buffer.concat([
    Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nSynthetic response ${exchangeID}\n`
      + 'Public fixture response line: captured bytes do not confirm a vulnerability.\n'.repeat(600)),
    // Include NUL and invalid UTF-8: exact downloads must not re-encode a preview.
    Buffer.from([0x00, 0xff, 0xfe, 0x80, 0x0d, 0x0a]),
  ]);
}

function receipt(entry: EvidenceEntry): EvidenceExchange {
  const method = entry.occurrence_id === GET_OCCURRENCE ? 'GET' : 'POST';
  const request = `${method} /reports/selected-evidence?fixture=public HTTP/1.1\r\nHost: example.test\r\n`
    + `X-Synthetic-Exchange: ${entry.exchange_id}\r\n`
    + 'X-Public-Fixture: captured request context\r\n'.repeat(350)
    + '\r\n' + (method === 'POST' ? 'fixture=public&selection=synthetic' : '');
  return {
    id: entry.exchange_id, url: FINDING_URL, service: 'example.test:443',
    request: Buffer.from(request).toString('base64'), response: responseBytes(entry.exchange_id).toString('base64'),
    request_state: 'complete', response_state: 'complete', provenance: 'captured',
    content_hash: `synthetic-content-hash-${entry.exchange_id}`, captured_at: '2026-11-01T12:01:00Z',
  };
}

function evidenceButton(root: Locator | Page, entry: EvidenceEntry): Locator {
  return root.getByRole('button', {
    name: new RegExp(` — role: ${entry.role} · primary declaration: ${entry.primary ? 'yes' : 'no'} — exchange: ${entry.exchange_id}$`),
  });
}

function assertScopedRead(route: Route) {
  expect(route.request().method()).toBe('GET');
  expect(route.request().headers()['x-project-uuid']).toBe(FIXTURE_PROJECT.uuid);
  expect(route.request().headers().authorization).toBe(`Bearer ${FIXTURE_API_KEY}`);
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

async function mockFinding(page: Page, finding = FINDING, delayed?: {
  exchangeID: string;
  release: Promise<void>;
  served: () => void;
}) {
  const evidenceRequests: string[] = [];
  const targetRequests: string[] = [];
  await page.route('https://example.test/**', route => {
    targetRequests.push(route.request().url());
    return route.abort(); // Fixture URLs must never cause real target traffic.
  });
  await page.route('**/api/findings?*', route => {
    assertScopedRead(route);
    return route.fulfill({ json: { data: [finding], total: 1, offset: 0, limit: 100, has_more: false } });
  });
  await page.route('**/api/findings/hosts*', route => {
    assertScopedRead(route);
    return route.fulfill({ json: { data: [{ hostname: 'example.test', total: 1 }], total: 1, has_more: false } });
  });
  await page.route(`**/api/findings/${FINDING_ID}`, route => {
    assertScopedRead(route);
    return route.fulfill({ json: finding });
  });
  await page.route(`**/api/findings/${FINDING_ID}/evidence/*`, async route => {
    assertScopedRead(route);
    const exchangeID = decodeURIComponent(new URL(route.request().url()).pathname.split('/').pop()!);
    const entry = finding.occurrences?.flatMap(group => group.entries).find(item => item.exchange_id === exchangeID);
    expect(entry, 'Only a manifest association may be hydrated').toBeDefined();
    evidenceRequests.push(exchangeID);
    if (delayed?.exchangeID === exchangeID) {
      await delayed.release;
      try {
        await route.fulfill({ json: receipt(entry!) });
      } finally {
        delayed.served();
      }
    } else {
      await route.fulfill({ json: receipt(entry!) });
    }
  });
  return { evidenceRequests, targetRequests };
}

async function openFinding(page: Page) {
  await page.goto(`/findings/?id=${FINDING_ID}`);
  const section = page.getByRole('region', { name: 'Selected evidence', exact: true });
  await expect(section).toBeVisible();
  await section.scrollIntoViewIfNeeded();
  return section;
}

/** Find an actual scroll owner inside the accessible region, not a CSS class. */
async function scrollState(region: Locator, top?: number) {
  return region.evaluate((root, requestedTop) => {
    const candidates = [root, ...root.querySelectorAll<HTMLElement>('*')];
    const owner = candidates.find(element => /^(auto|scroll)$/.test(getComputedStyle(element).overflowY)
      && element.scrollHeight > element.clientHeight && element.clientHeight > 0) as HTMLElement | undefined;
    if (!owner) throw new Error(`No bounded vertical scroll owner inside ${root.getAttribute('aria-label')}`);
    if (requestedTop !== undefined) owner.scrollTop = requestedTop;
    return {
      top: owner.scrollTop, scrollHeight: owner.scrollHeight, clientHeight: owner.clientHeight,
      overflowY: getComputedStyle(owner).overflowY,
    };
  }, top);
}

async function scrollingAncestors(region: Locator) {
  return region.evaluate(element => {
    const owners: string[] = [];
    for (let parent = element.parentElement; parent; parent = parent.parentElement) {
      if (/^(auto|scroll)$/.test(getComputedStyle(parent).overflowY) && parent.scrollHeight > parent.clientHeight) {
        owners.push(parent.getAttribute('aria-label') || parent.tagName);
      }
    }
    return owners;
  });
}

async function expectAdjacent(list: Locator, inspector: Locator) {
  const listBox = await list.boundingBox();
  const inspectorBox = await inspector.boundingBox();
  expect(listBox).not.toBeNull();
  expect(inspectorBox).not.toBeNull();
  expect(listBox!.x + listBox!.width).toBeLessThanOrEqual(inspectorBox!.x + 1);
  expect(Math.max(listBox!.y, inspectorBox!.y)).toBeLessThan(Math.min(
    listBox!.y + listBox!.height, inspectorBox!.y + inspectorBox!.height,
  )); // Genuine side-by-side vertical overlap, not a viewer appended after groups.
}

async function expectWithinViewport(page: Page, region: Locator) {
  const box = await region.boundingBox();
  const viewport = page.viewportSize()!;
  expect(box).not.toBeNull();
  expect(box!.x).toBeGreaterThanOrEqual(-1);
  expect(box!.y).toBeGreaterThanOrEqual(-1);
  expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width + 1);
  expect(box!.y + box!.height).toBeLessThanOrEqual(viewport.height + 1);
}

async function expectNoHorizontalOverflow(page: Page) {
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.viewport + 1);
  expect(dimensions.body).toBeLessThanOrEqual(dimensions.viewport + 1);
}

async function expectFindingStillOpen(page: Page) {
  await expect(page).toHaveURL(new RegExp(`/findings/\\?id=${FINDING_ID}$`));
  await expect(page.getByText(`FINDING #${FINDING_ID}`, { exact: true })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Selected evidence', exact: true })).toBeVisible();
}

for (const theme of ['dark', 'light'] as const) {
  test.describe(`${theme} selected evidence workspace`, () => {
    test.use({ viewport: { width: 1920, height: 760 } });
    test.beforeEach(async ({ page }) => {
      await seedAuth(page, { projectUUID: FIXTURE_PROJECT.uuid });
      await page.addInitScript(scheme => localStorage.setItem('vigolium_scheme', scheme), `default-${theme}`);
    });

    test('keeps compact detection navigation beside an independent inspector and expands into a bounded workspace', async ({ page, consoleErrors }) => {
      const mocked = await mockFinding(page);
      const section = await openFinding(page);
      const list = section.getByRole('region', { name: 'Evidence list', exact: true });
      const inspector = section.getByRole('complementary', { name: 'Evidence inspector', exact: true });
      // These deliberately fail against the old append-after-all-groups layout.
      await expect(inspector).toBeVisible();
      const opener = inspector.getByRole('button', { name: 'Expand evidence workspace', exact: true });
      await expect(opener).toBeVisible();
      await expectAdjacent(list, inspector);
      await expect(inspector.getByRole('region', { name: 'Selected request', exact: true })).toContainText('POST /reports/selected-evidence');
      // Next dev's StrictMode can start and abort an initial duplicate effect.
      // It may read the same receipt again, never another exchange or the corpus.
      expect([...new Set(mocked.evidenceRequests)]).toEqual([POST_PRIMARY.exchange_id]);
      const initialReadCount = mocked.evidenceRequests.length;
      await expect(evidenceButton(list, POST_PRIMARY)).toHaveAttribute('aria-pressed', 'true');
      await expect(evidenceButton(list, GET_PRIMARY)).toHaveAttribute('aria-pressed', 'false');
      await expect(section).not.toContainText('Multiple primary declarations');
      await expect(section).toContainText(/each detection keeps its own main selection/i);
      await expect(section).toContainText(/stored declarations, not vulnerability confirmation/i);

      const groups = list.getByRole('group', { name: /^Finding occurrence / });
      await expect(groups).toHaveCount(2);
      const latest = groups.nth(0);
      const oldest = groups.nth(1);
      await expect(latest).toHaveAccessibleName(`Finding occurrence ${SCAN_UUID} ${POST_OCCURRENCE}`);
      await expect(oldest).toHaveAccessibleName(`Finding occurrence ${SCAN_UUID} ${GET_OCCURRENCE}`);
      await expect(latest.getByRole('heading', { name: /^Detection 2/ })).toBeVisible();
      await expect(oldest.getByRole('heading', { name: 'Detection 1', exact: true })).toHaveCount(1);
      const compactText = await latest.evaluate(element => (element as HTMLElement).innerText);
      expect(compactText).toContain(SCAN_UUID.slice(0, 8));
      expect(compactText).not.toContain(SCAN_UUID);
      expect(compactText).not.toContain(POST_OCCURRENCE);
      expect(await evidenceButton(latest, POST_PRIMARY).innerText()).toMatch(/attack/i);
      expect(await evidenceButton(latest, POST_PRIMARY).innerText()).not.toContain(POST_PRIMARY.exchange_id);

      const detectionDetails = latest.locator('details').filter({
        has: page.locator('summary').filter({ hasText: /^Detection technical details$/ }),
      });
      await expect(detectionDetails).not.toHaveAttribute('open', '');
      await detectionDetails.locator('summary').click();
      await expect(detectionDetails).toContainText(SCAN_UUID);
      await expect(detectionDetails).toContainText(POST_OCCURRENCE);
      await detectionDetails.locator('summary').click();
      const exchangeDetails = latest.locator('details').filter({
        has: page.locator('summary').filter({ hasText: /^Exchange technical details$/ }),
      }).first();
      await expect(exchangeDetails).not.toHaveAttribute('open', '');
      await exchangeDetails.locator('summary').click();
      for (const value of [POST_PRIMARY.exchange_id, SCAN_UUID, POST_OCCURRENCE, POST_PRIMARY.label!, FINDING_URL]) {
        await expect(exchangeDetails).toContainText(value);
      }
      await exchangeDetails.locator('summary').click();
      expect(mocked.evidenceRequests).toHaveLength(initialReadCount); // Details do not fetch every exchange.

      await opener.click();
      const dialog = page.getByRole('dialog', { name: 'Finding evidence workspace', exact: true });
      await expect(dialog).toBeVisible();
      await expect(dialog).toHaveAttribute('aria-modal', 'true');
      expect(mocked.evidenceRequests).toHaveLength(initialReadCount); // Expanding retains the exact loaded bytes.
      const workspaceList = dialog.getByRole('region', { name: 'Evidence list', exact: true });
      const workspaceInspector = dialog.getByRole('complementary', { name: 'Evidence inspector', exact: true });
      await expectAdjacent(workspaceList, workspaceInspector);
      await expectWithinViewport(page, dialog);
      await expectWithinViewport(page, workspaceList);
      await expectWithinViewport(page, workspaceInspector);
      expect(await scrollingAncestors(dialog)).toEqual([]); // Portal is outside the finding/page scroll owners.
      expect(await scrollingAncestors(workspaceList)).toEqual([]);
      expect(await scrollingAncestors(workspaceInspector)).toEqual([]);
      const navigationScroll = await scrollState(workspaceList, 400);
      expect(navigationScroll.overflowY).toMatch(/^(auto|scroll)$/);
      expect(navigationScroll.scrollHeight).toBeGreaterThan(navigationScroll.clientHeight);
      expect(navigationScroll.top).toBeGreaterThan(0);
      // Pick a fully visible row so Playwright's click cannot itself scroll the list.
      const visibleName = await workspaceList.evaluate(root => {
        const bounds = root.getBoundingClientRect();
        return [...root.querySelectorAll<HTMLButtonElement>('button[aria-pressed="false"]')].find(button => {
          const box = button.getBoundingClientRect();
          if (box.height <= 0 || box.top < bounds.top || box.bottom > bounds.bottom) return false;
          for (let parent = button.parentElement; parent && parent !== root; parent = parent.parentElement) {
            if (!/^(auto|scroll|hidden|clip)$/.test(getComputedStyle(parent).overflowY)) continue;
            const clip = parent.getBoundingClientRect();
            if (box.top < clip.top || box.bottom > clip.bottom) return false;
          }
          return true;
        })?.getAttribute('aria-label');
      });
      expect(visibleName).toBeTruthy();
      const selectedID = visibleName!.split(' — exchange: ')[1];
      const beforeClick = (await scrollState(workspaceList)).top;
      expect((await scrollState(workspaceInspector, 150)).top).toBeGreaterThan(0);
      await workspaceList.getByRole('button', { name: visibleName!, exact: true }).click();
      const response = workspaceInspector.getByRole('region', { name: 'Selected response', exact: true });
      await expect(response).toContainText(`Synthetic response ${selectedID}`);
      expect(Math.abs((await scrollState(workspaceList)).top - beforeClick)).toBeLessThanOrEqual(1);
      expect((await scrollState(workspaceInspector)).top).toBe(0);

      // Native Tab traversal must reach the independently scrollable final preview.
      await response.getByRole('button', { name: 'Download exact bytes', exact: true }).focus();
      await page.keyboard.press('Tab');
      await expect(response.locator('pre')).toBeFocused();
      await page.keyboard.press('Tab');
      await expect(dialog.getByRole('button', { name: 'Close evidence workspace', exact: true })).toBeFocused();
      await page.keyboard.press('Shift+Tab');
      await expect(response.locator('pre')).toBeFocused();

      const downloadEvent = page.waitForEvent('download');
      await response.getByRole('button', { name: 'Download exact bytes', exact: true }).click();
      const download = await downloadEvent;
      expect(await download.failure()).toBeNull();
      const stream = await download.createReadStream();
      expect(stream).not.toBeNull();
      const chunks: Buffer[] = [];
      for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
      expect(Buffer.concat(chunks)).toEqual(responseBytes(selectedID));

      await dialog.getByRole('button', { name: 'Close evidence workspace', exact: true }).click();
      await expect(dialog).toHaveCount(0);
      await expect(opener).toBeFocused();
      await expectFindingStillOpen(page);
      await opener.click();
      await expect(dialog).toBeVisible();
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveCount(0);
      await expect(opener).toBeFocused();
      await expectFindingStillOpen(page); // Escape must not reach the page's finding-close handler.
      expect(mocked.targetRequests).toEqual([]);
      expect(consoleErrors.errors).toEqual([]);
      expect(consoleErrors.unhandled).toEqual([]);
    });

    test('opens a one-column workspace directly from evidence selection at 375px without horizontal page overflow', async ({ page, consoleErrors }) => {
      await page.setViewportSize({ width: 375, height: 812 });
      const mocked = await mockFinding(page);
      const section = await openFinding(page);
      await expectNoHorizontalOverflow(page);
      const opener = evidenceButton(section.getByRole('region', { name: 'Evidence list', exact: true }), POST_PRIMARY);
      await opener.click();
      const dialog = page.getByRole('dialog', { name: 'Finding evidence workspace', exact: true });
      await expect(dialog).toBeVisible();
      await expect(dialog).toHaveAttribute('aria-modal', 'true');
      const list = dialog.getByRole('region', { name: 'Evidence list', exact: true });
      const inspector = dialog.getByRole('complementary', { name: 'Evidence inspector', exact: true });
      await expect(inspector.getByRole('region', { name: 'Selected request', exact: true })).toContainText('POST /reports/selected-evidence');
      await expectWithinViewport(page, dialog);
      await expectWithinViewport(page, list);
      await expectWithinViewport(page, inspector);
      const listBox = (await list.boundingBox())!;
      const inspectorBox = (await inspector.boundingBox())!;
      expect(listBox.y + listBox.height).toBeLessThanOrEqual(inspectorBox.y + 1);
      expect(Math.max(listBox.x, inspectorBox.x)).toBeLessThan(Math.min(listBox.x + listBox.width, inspectorBox.x + inspectorBox.width));
      expect(listBox.height).toBeLessThan(inspectorBox.height);
      expect((await scrollState(list)).scrollHeight).toBeGreaterThan((await scrollState(list)).clientHeight);
      expect(await scrollingAncestors(dialog)).toEqual([]);
      await expectNoHorizontalOverflow(page);
      await dialog.getByRole('button', { name: 'Close evidence workspace', exact: true }).click();
      await expect(dialog).toHaveCount(0);
      await expect(opener).toBeFocused();
      await expectFindingStillOpen(page);
      await expectNoHorizontalOverflow(page);
      expect(mocked.targetRequests).toEqual([]);
      expect(consoleErrors.errors).toEqual([]);
      expect(consoleErrors.unhandled).toEqual([]);
    });

    test('restores nested context details, navigation scroll and opener focus after closing on mobile', async ({ page, consoleErrors }) => {
      await page.setViewportSize({ width: 375, height: 812 });
      const contextEntry: EvidenceEntry = {
        ...POST_DETECTION.entries[13], label: 'Scan input / context',
      };
      const detection: FindingOccurrence = {
        ...POST_DETECTION, entries: [POST_PRIMARY, contextEntry],
      };
      const mocked = await mockFinding(page, {
        ...FINDING, occurrences: [detection], evidence: detection.entries,
      });
      const section = await openFinding(page);
      const list = section.getByRole('region', { name: 'Evidence list', exact: true });
      const summaryName = 'Scan input / context (context only)';
      const context = list.locator('details').filter({
        has: page.locator('summary').filter({ hasText: /^Scan input \/ context \(context only\)$/ }),
      });
      await context.getByText(summaryName, { exact: true }).click();
      await context.getByText('Exchange technical details', { exact: true }).click();
      const opener = evidenceButton(context, contextEntry);

      for (const closeMethod of ['button', 'Escape']) {
        await opener.scrollIntoViewIfNeeded();
        await opener.focus();
        const inlineTop = (await scrollState(list)).top;
        await opener.click();
        const dialog = page.getByRole('dialog', { name: 'Finding evidence workspace', exact: true });
        await expect(dialog).toBeVisible();
        await expect(dialog.getByRole('region', { name: 'Selected response', exact: true })).toContainText(`Synthetic response ${contextEntry.exchange_id}`);
        const expandedContext = dialog.locator('details').filter({
          has: page.locator('summary').filter({ hasText: /^Scan input \/ context \(context only\)$/ }),
        });
        await expect(expandedContext).toHaveAttribute('open', '');
        await expect(expandedContext.locator('details')).toHaveAttribute('open', '');
        if (closeMethod === 'button') await dialog.getByRole('button', { name: 'Close evidence workspace', exact: true }).click();
        else await page.keyboard.press('Escape');
        await expect(dialog).toHaveCount(0);
        await expect(context).toHaveAttribute('open', '');
        await expect(context.locator('details')).toHaveAttribute('open', '');
        await expect(opener).toBeVisible();
        await expect(opener).toBeFocused();
        expect(Math.abs((await scrollState(list)).top - inlineTop)).toBeLessThanOrEqual(1);
        await expectFindingStillOpen(page);
        await expectNoHorizontalOverflow(page);
      }
      // A user can fold the opener's group inside the modal. Preserve that choice
      // and focus its visible summary, not the now-hidden exchange button.
      for (const closeMethod of ['button', 'Escape']) {
        if (await context.getAttribute('open') === null) await context.getByText(summaryName, { exact: true }).click();
        await opener.click();
        const dialog = page.getByRole('dialog', { name: 'Finding evidence workspace', exact: true });
        await expect(dialog.getByRole('region', { name: 'Selected response', exact: true })).toContainText(`Synthetic response ${contextEntry.exchange_id}`);
        await dialog.getByText(summaryName, { exact: true }).click();
        if (closeMethod === 'button') await dialog.getByRole('button', { name: 'Close evidence workspace', exact: true }).click();
        else await page.keyboard.press('Escape');
        await expect(dialog).toHaveCount(0);
        await expect(context).not.toHaveAttribute('open', '');
        await expect(context.locator('button[data-evidence-key]')).not.toBeVisible();
        await expect(context.getByText(summaryName, { exact: true })).toBeVisible();
        await expect(context.getByText(summaryName, { exact: true })).toBeFocused();
        await expectFindingStillOpen(page);
        await expectNoHorizontalOverflow(page);
      }
      expect(new Set(mocked.evidenceRequests)).toEqual(new Set([POST_PRIMARY.exchange_id, contextEntry.exchange_id]));
      expect(mocked.targetRequests).toEqual([]);
      expect(consoleErrors.errors).toEqual([]);
      expect(consoleErrors.unhandled).toEqual([]);
    });

    test('also opens directly when the desktop finding panel offers less than 700px', async ({ page, consoleErrors }) => {
      await page.setViewportSize({ width: 1100, height: 760 });
      const mocked = await mockFinding(page);
      const section = await openFinding(page);
      expect((await section.boundingBox())!.width).toBeLessThan(700);
      const opener = evidenceButton(section.getByRole('region', { name: 'Evidence list', exact: true }), GET_PRIMARY);
      await opener.click();
      const dialog = page.getByRole('dialog', { name: 'Finding evidence workspace', exact: true });
      await expect(dialog).toBeVisible();
      const list = dialog.getByRole('region', { name: 'Evidence list', exact: true });
      const inspector = dialog.getByRole('complementary', { name: 'Evidence inspector', exact: true });
      await expect(inspector.getByRole('region', { name: 'Selected request', exact: true })).toContainText('GET /reports/selected-evidence');
      await expect(evidenceButton(list, GET_PRIMARY)).toHaveAttribute('aria-pressed', 'true');
      await expectAdjacent(list, inspector);
      await expectWithinViewport(page, dialog);
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveCount(0);
      await expect(opener).toBeFocused();
      await expectFindingStillOpen(page);
      expect(mocked.evidenceRequests).toContain(GET_PRIMARY.exchange_id);
      expect(mocked.targetRequests).toEqual([]);
      expect(consoleErrors.errors).toEqual([]);
      expect(consoleErrors.unhandled).toEqual([]);
    });

    test('does not let a delayed previous receipt overwrite the newly selected exchange', async ({ page, consoleErrors }) => {
      const release = deferred();
      const served = deferred();
      const delayedEntry = POST_DETECTION.entries[1];
      const mocked = await mockFinding(page, FINDING, {
        exchangeID: delayedEntry.exchange_id, release: release.promise, served: served.resolve,
      });
      try {
        const section = await openFinding(page);
        const list = section.getByRole('region', { name: 'Evidence list', exact: true });
        const inspector = section.getByRole('complementary', { name: 'Evidence inspector', exact: true });
        await expect(inspector).toContainText(`Synthetic response ${POST_PRIMARY.exchange_id}`);
        await evidenceButton(list, delayedEntry).click();
        await expect.poll(() => mocked.evidenceRequests.includes(delayedEntry.exchange_id)).toBe(true);
        await evidenceButton(list, POST_PRIMARY).click();
        await expect(inspector).toContainText(`Synthetic response ${POST_PRIMARY.exchange_id}`);
        release.resolve();
        await served.promise;
        // Allow the released response's promise handlers to run without a timing sleep.
        await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
        await expect(inspector).toContainText(`Synthetic response ${POST_PRIMARY.exchange_id}`);
        await expect(inspector).not.toContainText(`Synthetic response ${delayedEntry.exchange_id}`);
        await expect(evidenceButton(list, POST_PRIMARY)).toHaveAttribute('aria-pressed', 'true');
        await expect(page.getByRole('dialog', { name: 'Finding evidence workspace', exact: true })).toHaveCount(0);
        expect(mocked.targetRequests).toEqual([]);
        expect(consoleErrors.errors).toEqual([]);
        expect(consoleErrors.unhandled).toEqual([]);
      } finally {
        release.resolve();
      }
    });

    test('does not auto-fetch an older detection when the newest primary declarations are ambiguous', async ({ page, consoleErrors }) => {
      const competingPrimary: EvidenceEntry = { ...POST_DETECTION.entries[1], role: 'confirmation', primary: true };
      const latest: FindingOccurrence = {
        ...POST_DETECTION, evidence_status: 'missing',
        entries: [POST_PRIMARY, competingPrimary, ...POST_DETECTION.entries.slice(2)],
      };
      const ambiguous: Finding = {
        ...FINDING, evidence_status: 'missing', occurrences: [GET_DETECTION, latest],
        evidence: [...GET_DETECTION.entries, ...latest.entries],
      };
      const mocked = await mockFinding(page, ambiguous);
      const section = await openFinding(page);
      await expect(section.getByRole('alert')).toContainText(/ambiguous primary declarations/i);
      const list = section.getByRole('region', { name: 'Evidence list', exact: true });
      for (const entry of [GET_PRIMARY, POST_PRIMARY, competingPrimary]) {
        await expect(evidenceButton(list, entry)).toHaveAttribute('aria-pressed', 'false');
      }
      expect(mocked.evidenceRequests).toEqual([]);
      await evidenceButton(list, POST_PRIMARY).click();
      await expect(section.getByRole('complementary', { name: 'Evidence inspector', exact: true })).toContainText(`Synthetic response ${POST_PRIMARY.exchange_id}`);
      expect(mocked.evidenceRequests).toEqual([POST_PRIMARY.exchange_id]);
      await expect(section).toContainText(/stored declarations, not vulnerability confirmation/i);
      expect(mocked.targetRequests).toEqual([]);
      expect(consoleErrors.errors).toEqual([]);
      expect(consoleErrors.unhandled).toEqual([]);
    });
  });
}
