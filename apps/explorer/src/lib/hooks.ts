import { useEffect, useRef, useState, useCallback } from "react";

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  refresh: () => void;
}

// Run an async loader, optionally polling every `intervalMs`. Keeps prior data
// visible while refreshing (no flash of empty state).
export function useAsync<T>(
  loader: () => Promise<T>,
  deps: any[] = [],
  intervalMs = 0
): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const alive = useRef(true);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  const run = useCallback(async () => {
    try {
      const d = await loaderRef.current();
      if (!alive.current) return;
      setData(d);
      setError(null);
    } catch (e: any) {
      if (!alive.current) return;
      setError(e?.message || String(e));
    } finally {
      if (alive.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    alive.current = true;
    setLoading(true);
    run();
    let t: number | undefined;
    if (intervalMs > 0) t = window.setInterval(run, intervalMs);
    return () => {
      alive.current = false;
      if (t) clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, refresh: run };
}
