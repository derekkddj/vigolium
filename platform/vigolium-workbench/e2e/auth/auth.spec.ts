import { test, expect, FIXTURE_API_KEY } from '../fixtures';

// AuthGate's flow:
//   1. fetch('/server-info') with NO auth header. 200 → "noAuth" mode, skip login.
//   2. Else: check localStorage token. If present, fetch('/server-info') with
//      Bearer header; 200 → ready.
//   3. Else: render the login UI (api-key tab + credentials tab).
//
// Each test below picks the branch it wants by overriding /server-info before
// navigation. Specs run after `installApiMocks`, and Playwright matches LIFO
// — these overrides take precedence.

test.describe('AuthGate — no-auth backend', () => {
  test('skips the login form when /server-info is open', async ({ page }) => {
    // Default fixture already returns 200 for /server-info without a token,
    // so AuthGate goes straight to ready.
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('text=Vigolium Workbench').first()).toHaveCount(0).catch(() => {});
    // The login card has the "Sign in" submit button. Its absence is the
    // signal that we're past the gate.
    await expect(page.getByRole('button', { name: /sign in/i })).toHaveCount(0);
  });
});

test.describe('AuthGate — auth required', () => {
  // Force the login UI: anonymous /server-info returns 401, only the bearer
  // path 200s.
  test.beforeEach(async ({ page }) => {
    await page.route('**/server-info', async (route) => {
      const auth = route.request().headers()['authorization'] ?? '';
      // Accept both the API key and the token issued by the login fixture;
      // otherwise the dashboard's first server-info poll logs the user out.
      if (auth === `Bearer ${FIXTURE_API_KEY}` || auth === 'Bearer e2e-issued-token') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ name: 'vigolium', version: 'e2e-test' }),
        });
        return;
      }
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'unauthorized', code: 401 }),
      });
    });
  });

  test('renders the login form when no token is stored', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible();
    await expect(page.getByText(/api key/i).first()).toBeVisible();
    await expect(page.getByText(/credentials/i).first()).toBeVisible();
  });

  test('valid api key signs in and reveals the app', async ({ page }) => {
    await page.goto('/');
    await page.getByPlaceholder(/vgl_/).fill(FIXTURE_API_KEY);
    await page.getByRole('button', { name: /sign in/i }).click();

    // Wait for persistence and the ready branch, not the temporary spinner.
    await expect.poll(() => page.evaluate(() =>
      window.localStorage.getItem('vigolium_api_token'),
    )).toBe(FIXTURE_API_KEY);
    await expect(page.getByPlaceholder(/vgl_/)).toHaveCount(0);
  });

  test('invalid api key surfaces an error and stays on the login form', async ({ page }) => {
    await page.goto('/');
    await page.getByPlaceholder(/vgl_/).fill('vgl_wrong_key');
    await page.getByRole('button', { name: /sign in/i }).click();

    await expect(page.getByText(/invalid api key/i)).toBeVisible({ timeout: 5_000 });
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible();

    const stored = await page.evaluate(() =>
      window.localStorage.getItem('vigolium_api_token'),
    );
    expect(stored).toBeNull();
  });

  test('credentials login succeeds via /api/auth/login', async ({ page }) => {
    await page.goto('/');
    // Switch to credentials tab.
    await page.getByRole('button', { name: /^credentials$/i }).click();

    await page.getByPlaceholder('username').fill('tester');
    await page.getByPlaceholder('access code').fill('correct-code');
    await page.getByRole('button', { name: /sign in/i }).click();

    await expect(page.getByRole('button', { name: /sign in/i })).toHaveCount(0, {
      timeout: 5_000,
    });

    // The button also loses its "Sign in" name while showing the spinner, so
    // its disappearance is not evidence that the login response has settled.
    await expect.poll(() => page.evaluate(() =>
      window.localStorage.getItem('vigolium_api_token'),
    )).toBe('e2e-issued-token');
    await expect(page.getByPlaceholder('username')).toHaveCount(0);
  });

  test('credentials login surfaces backend error message', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: /^credentials$/i }).click();
    await page.getByPlaceholder('username').fill('tester');
    // The fixture returns 401 when access_code === 'wrong'.
    await page.getByPlaceholder('access code').fill('wrong');
    await page.getByRole('button', { name: /sign in/i }).click();

    await expect(page.getByText(/invalid credentials/i)).toBeVisible({ timeout: 5_000 });
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible();
  });
});

test.describe('AuthGate — stored token', () => {
  // Stored token bypasses the login form when /server-info accepts it.
  test('app boots straight to ready when localStorage holds a valid token', async ({ page }) => {
    await page.route('**/server-info', async (route) => {
      const auth = route.request().headers()['authorization'] ?? '';
      const status = auth.startsWith('Bearer ') ? 200 : 401;
      await route.fulfill({
        status,
        contentType: 'application/json',
        body: JSON.stringify(status === 200 ? { name: 'vigolium' } : { error: 'unauthorized', code: 401 }),
      });
    });
    await page.addInitScript((token) => {
      window.localStorage.setItem('vigolium_api_token', token);
    }, FIXTURE_API_KEY);

    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await expect(page.getByRole('button', { name: /sign in/i })).toHaveCount(0);
  });
});
