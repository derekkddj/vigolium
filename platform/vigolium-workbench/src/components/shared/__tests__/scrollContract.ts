/** Structural scroll contract; browser E2E also checks computed styles and geometry. */
export function scrollOwners(el: Element): Element[] {
  const owners: Element[] = [];
  for (let current: Element | null = el; current; current = current.parentElement) {
    if (/(^|\s)(overflow(-y)?-(auto|scroll)|max-h-\S+)(\s|$)/.test(current.className)) owners.push(current);
  }
  return owners;
}
