export const base = import.meta.env.BASE_URL.replace(/\/$/, '');

/** Prefix an absolute site path with the configured base (Pages path prefix). */
export function url(path: string): string {
  if (!path.startsWith('/')) return path;
  return `${base}${path}`;
}
