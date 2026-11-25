import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import FindingsPagination from '../FindingsPagination';

const pages = [
  { offset: 0, returned: 100, page: 1, range: '1–100 of 260 findings', hasMore: true },
  { offset: 100, returned: 100, page: 2, range: '101–200 of 260 findings', hasMore: true },
  { offset: 200, returned: 60, page: 3, range: '201–260 of 260 findings', hasMore: false },
];

const baseProps = { offset: 0, pageSize: 100, returned: 100, total: 260, busy: false };

describe('FindingsPagination', () => {
  it.each(pages)('shows accessible controls and the returned range on page $page of 260 findings', ({ offset, returned, page, range, hasMore }) => {
    const onPageChange = vi.fn();
    render(<FindingsPagination {...baseProps} offset={offset} returned={returned} hasMore={hasMore} onPageChange={onPageChange} />);

    const navigation = screen.getByRole('navigation', { name: 'Findings pagination' });
    expect(navigation).toHaveAttribute('aria-busy', 'false');
    expect(within(navigation).getByText(range)).toHaveAttribute('aria-live', 'polite');
    expect(within(navigation).getByText(`Page ${page} of 3`)).toBeInTheDocument();
    const previous = within(navigation).getByRole('button', { name: 'Previous' });
    const next = within(navigation).getByRole('button', { name: 'Next' });
    expect(previous).toHaveAttribute('type', 'button');
    expect(next).toHaveAttribute('type', 'button');
    if (page === 1) expect(previous).toBeDisabled();
    else expect(previous).toBeEnabled();
    if (hasMore) expect(next).toBeEnabled();
    else expect(next).toBeDisabled();

    fireEvent.click(previous);
    fireEvent.click(next);
    const expectedPages = [
      ...(page > 1 ? [page - 1] : []),
      ...(hasMore ? [page + 1] : []),
    ];
    expect(onPageChange.mock.calls).toEqual(expectedPages.map((value) => [value]));
  });

  it('moves forward through all three server pages and back using one-based page handlers', () => {
    const onPageChange = vi.fn();
    const { rerender } = render(<FindingsPagination {...baseProps} hasMore onPageChange={onPageChange} />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(onPageChange).toHaveBeenLastCalledWith(2);

    rerender(<FindingsPagination {...baseProps} offset={100} hasMore onPageChange={onPageChange} />);
    expect(screen.getByText('Page 2 of 3')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(onPageChange).toHaveBeenLastCalledWith(3);

    rerender(<FindingsPagination {...baseProps} offset={200} returned={60} hasMore={false} onPageChange={onPageChange} />);
    expect(screen.getByText('201–260 of 260 findings')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }));
    expect(onPageChange).toHaveBeenLastCalledWith(2);

    rerender(<FindingsPagination {...baseProps} offset={100} hasMore onPageChange={onPageChange} />);
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }));
    expect(onPageChange.mock.calls).toEqual([[2], [3], [2], [1]]);
  });

  it.each(pages)('disables both handlers and announces loading while page $page is busy', ({ offset, returned, hasMore, range }) => {
    const onPageChange = vi.fn();
    const { rerender } = render(<FindingsPagination {...baseProps} offset={offset} returned={returned} hasMore={hasMore} busy onPageChange={onPageChange} />);
    expect(screen.getByRole('navigation', { name: 'Findings pagination' })).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByText('Loading findings…')).toHaveAttribute('aria-live', 'polite');
    expect(screen.queryByText(range)).not.toBeInTheDocument();
    const previous = screen.getByRole('button', { name: 'Previous' });
    const next = screen.getByRole('button', { name: 'Next' });
    expect(previous).toBeDisabled();
    expect(next).toBeDisabled();
    fireEvent.click(previous);
    fireEvent.click(next);
    expect(onPageChange).not.toHaveBeenCalled();

    rerender(<FindingsPagination {...baseProps} offset={offset} returned={returned} hasMore={hasMore} onPageChange={onPageChange} />);
    expect(screen.getByRole('navigation', { name: 'Findings pagination' })).toHaveAttribute('aria-busy', 'false');
    expect(screen.getByText(range)).toBeInTheDocument();
    expect(screen.queryByText('Loading findings…')).not.toBeInTheDocument();
  });

  it('uses explicit hasMore=false even when the total suggests another page', () => {
    const onPageChange = vi.fn();
    render(<FindingsPagination {...baseProps} hasMore={false} onPageChange={onPageChange} />);
    const next = screen.getByRole('button', { name: 'Next' });
    expect(next).toBeDisabled();
    fireEvent.click(next);
    expect(onPageChange).not.toHaveBeenCalled();
  });

  it('uses explicit hasMore=true even when the total suggests the last page', () => {
    const onPageChange = vi.fn();
    render(<FindingsPagination {...baseProps} offset={200} returned={60} hasMore onPageChange={onPageChange} />);
    expect(screen.getByText('Page 3 of 3')).toBeInTheDocument();
    const next = screen.getByRole('button', { name: 'Next' });
    expect(next).toBeEnabled();
    fireEvent.click(next);
    expect(onPageChange).toHaveBeenCalledExactlyOnceWith(4);
  });

  it.each(pages)('falls back to offset and total when hasMore is omitted on page $page', ({ offset, returned, page }) => {
    const onPageChange = vi.fn();
    render(<FindingsPagination {...baseProps} offset={offset} returned={returned} onPageChange={onPageChange} />);
    const next = screen.getByRole('button', { name: 'Next' });
    if (page < 3) expect(next).toBeEnabled();
    else expect(next).toBeDisabled();
    fireEvent.click(next);
    expect(onPageChange.mock.calls).toEqual(page < 3 ? [[page + 1]] : []);
  });

  it('does not offer an extra fallback page when total is an exact page-size multiple', () => {
    const onPageChange = vi.fn();
    render(<FindingsPagination {...baseProps} offset={100} total={200} onPageChange={onPageChange} />);
    expect(screen.getByText('Page 2 of 2')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
  });

  it('uses the actual returned count for a partial page instead of assuming pageSize', () => {
    render(<FindingsPagination {...baseProps} offset={100} returned={12} hasMore onPageChange={vi.fn()} />);
    expect(screen.getByText('101–112 of 260 findings')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled();
  });

  it('shows an empty range and one page without enabling navigation for zero findings', () => {
    const onPageChange = vi.fn();
    render(<FindingsPagination {...baseProps} returned={0} total={0} onPageChange={onPageChange} />);
    expect(screen.getByText('0–0 of 0 findings')).toBeInTheDocument();
    expect(screen.getByText('Page 1 of 1')).toBeInTheDocument();
    const previous = screen.getByRole('button', { name: 'Previous' });
    const next = screen.getByRole('button', { name: 'Next' });
    expect(previous).toBeDisabled();
    expect(next).toBeDisabled();
    fireEvent.click(previous);
    fireEvent.click(next);
    expect(onPageChange).not.toHaveBeenCalled();
  });
});
