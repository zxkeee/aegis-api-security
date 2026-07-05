import { useCallback, useEffect, useRef, useState } from "react";

interface DataState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

/** useData fetches on mount, polls on an optional interval, and exposes refresh. */
export function useData<T>(fetcher: () => Promise<T>, deps: unknown[] = [], pollMs = 0): DataState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const fRef = useRef(fetcher);
  fRef.current = fetcher;

  const load = useCallback(async () => {
    try {
      const d = await fRef.current();
      setData(d);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "request failed");
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    setLoading(true);
    load();
    if (pollMs > 0) {
      const id = setInterval(load, pollMs);
      return () => clearInterval(id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, loading, error, refresh: load };
}
