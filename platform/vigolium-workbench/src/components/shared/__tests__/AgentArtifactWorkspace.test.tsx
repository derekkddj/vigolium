import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setBaseUrl, setToken } from '@/api/client';
import AgentArtifactsPanel from '../AgentArtifactsPanel';
import { scrollOwners } from './scrollContract';

const context = vi.hoisted(() => ({ projectUUID: 'project-a' }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => context }));
const items = [{ name: 'auth-config.yaml', kind: 'yaml', size: 4 }, { name: 'second.txt', kind: 'text', size: 4 }];
const listing = () => new Response(JSON.stringify({ artifacts: items, truncated: true }));
const page = (text: string, total = 4) => new Response(text, { headers: { 'X-Artifact-Total-Size': String(total), 'X-Artifact-Offset': '0', 'X-Artifact-Returned-Bytes': String(text.length), 'X-Artifact-Truncated': total > text.length ? '1' : '0' } });

beforeEach(() => {
  setBaseUrl('https://api.example.invalid'); setToken('fixture-secret');
  vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(listing()).mockResolvedValueOnce(page('head')));
});

for (const theme of ['dark', 'light'] as const) {
  describe(`${theme} full-height workspace`, () => {
    it('opens outside page scroll owners and gives the file content and sidebar independent scrolls', async () => {
      const { container } = render(<div className="overflow-auto max-h-[300px]"><AgentArtifactsPanel runUUID="run-a" theme={theme} /></div>);
      fireEvent.click(await screen.findByRole('button', { name: 'auth-config.yaml' }));
      const dialog = screen.getByRole('dialog', { name: 'Run artifacts workspace' });
      expect(await within(dialog).findByText('head', { exact: true })).toBeInTheDocument();
      const pre = within(dialog).getByLabelText('Artifact content');
      const list = within(dialog).getByRole('navigation', { name: 'Workspace artifact files' });
      expect(scrollOwners(pre)).toEqual([pre]);
      expect(scrollOwners(list)).toEqual([list]);
      expect(pre.className).not.toMatch(/max-h-/);
      expect(pre.contains(list) || list.contains(pre)).toBe(false);
      expect(container.contains(dialog)).toBe(false);
      expect(dialog).toHaveAttribute('aria-modal', 'true');
    });

    it.each(['Escape', 'button'])('closes with %s, unlocks the background and returns focus to the opener', async (method) => {
      const previous = document.body.style.overflow;
      document.body.style.overflow = 'clip';
      const { unmount } = render(<AgentArtifactsPanel runUUID="run-a" theme={theme} />);
      const opener = await screen.findByRole('button', { name: 'auth-config.yaml' });
      opener.focus(); fireEvent.click(opener);
      const dialog = screen.getByRole('dialog', { name: 'Run artifacts workspace' });
      expect(document.body.style.overflow).toBe('hidden');
      const close = within(dialog).getByRole('button', { name: 'Close artifacts workspace' });
      expect(close).toHaveFocus();
      if (method === 'Escape') fireEvent.keyDown(close, { key: 'Escape' }); else fireEvent.click(close);
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(opener).toHaveFocus();
      expect(document.body.style.overflow).toBe('clip');
      unmount(); document.body.style.overflow = previous;
    });

    it('restores the previous overflow on unmount and traps keyboard focus in the workspace', async () => {
      const previous = document.body.style.overflow;
      const { unmount } = render(<AgentArtifactsPanel runUUID="run-a" theme={theme} />);
      fireEvent.click(await screen.findByRole('button', { name: 'auth-config.yaml' }));
      const dialog = screen.getByRole('dialog', { name: 'Run artifacts workspace' });
      const close = within(dialog).getByRole('button', { name: 'Close artifacts workspace' });
      fireEvent.keyDown(close, { key: 'Tab', shiftKey: true });
      expect(dialog.contains(document.activeElement)).toBe(true);
      expect(close).not.toHaveFocus();
      unmount(); expect(document.body.style.overflow).toBe(previous);
    });

    it('closes with Escape even when a disabled action has dropped focus outside the dialog', async () => {
      render(<AgentArtifactsPanel runUUID="run-a" theme={theme} />);
      const opener = await screen.findByRole('button', { name: 'auth-config.yaml' });
      opener.focus(); fireEvent.click(opener);
      const close = screen.getByRole('button', { name: 'Close artifacts workspace' });
      await screen.findByLabelText('Artifact content');
      close.blur();
      expect(document.activeElement).toBe(document.body);
      fireEvent.keyDown(document.body, { key: 'Escape' });
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(opener).toHaveFocus();
      expect(fireEvent.keyDown(document.body, { key: 'Escape' })).toBe(true);
    });

    it.each([false, true])('recovers Tab focus from outside the dialog (shift=%s) and removes its listener on unmount', async (shiftKey) => {
      const { unmount } = render(<AgentArtifactsPanel runUUID="run-a" theme={theme} />);
      fireEvent.click(await screen.findByRole('button', { name: 'auth-config.yaml' }));
      const dialog = screen.getByRole('dialog');
      await within(dialog).findByLabelText('Artifact content');
      screen.getByRole('button', { name: 'Close artifacts workspace' }).blur();
      expect(fireEvent.keyDown(document.body, { key: 'Tab', shiftKey })).toBe(false);
      expect(dialog.contains(document.activeElement)).toBe(true);
      if (!shiftKey) expect(within(dialog).getByRole('button', { name: 'Close artifacts workspace' })).toHaveFocus();
      unmount();
      expect(fireEvent.keyDown(document.body, { key: 'Tab', shiftKey })).toBe(true);
    });

    it('keeps long notes collapsed and truncation/binary statuses outside the notes', async () => {
      vi.mocked(fetch).mockReset().mockResolvedValueOnce(listing()).mockResolvedValueOnce(new Response(Uint8Array.from([255, 0, 65, 10]), { headers: { 'X-Artifact-Total-Size': '8', 'X-Artifact-Offset': '0', 'X-Artifact-Returned-Bytes': '4', 'X-Artifact-Truncated': '1' } }));
      render(<AgentArtifactsPanel runUUID="run-a" theme={theme} />);
      fireEvent.click(await screen.findByRole('button', { name: 'auth-config.yaml' }));
      const dialog = screen.getByRole('dialog', { name: 'Run artifacts workspace' });
      const notes = within(dialog).getByText('Preview limits and download notes').closest('details')!;
      expect(notes).not.toHaveAttribute('open');
      expect(notes).toHaveTextContent('${VIGOLIUM_TOKEN:?Set token locally}');
      const binary = await within(dialog).findByText(/Invalid UTF-8 or binary\/control bytes/);
      expect(notes.contains(binary)).toBe(false);
      expect(notes.contains(within(dialog).getByText(/Partial preview — bytes have been omitted/))).toBe(false);
      expect(within(dialog).getByRole('button', { name: 'Copy visible page' })).toBeDisabled();
    });

    it('aborts the previous selected file and ignores its late response when choosing in the sidebar', async () => {
      let resolve!: (value: Response) => void;
      const late = new Promise<Response>(done => { resolve = done; });
      vi.mocked(fetch).mockReset().mockResolvedValueOnce(listing()).mockReturnValueOnce(late).mockResolvedValueOnce(page('next'));
      render(<AgentArtifactsPanel runUUID="run-a" theme={theme} />);
      fireEvent.click(await screen.findByRole('button', { name: 'auth-config.yaml' }));
      const signal = vi.mocked(fetch).mock.calls[1][1]?.signal;
      const dialog = screen.getByRole('dialog', { name: 'Run artifacts workspace' });
      fireEvent.click(within(dialog).getByRole('button', { name: 'second.txt' }));
      expect(signal?.aborted).toBe(true);
      expect(await within(dialog).findByText('next', { exact: true })).toBeInTheDocument();
      await act(async () => { resolve(page('late')); });
      expect(within(dialog).queryByText('late', { exact: true })).not.toBeInTheDocument();
      expect(fetch).toHaveBeenCalledTimes(3);
    });
  });
}
