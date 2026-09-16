import { useEffect, useMemo, useReducer } from 'react';

export const initialPageDataState = {
  status: 'loading',
  data: null,
  error: null,
};

export function pageDataReducer(state, action) {
  switch (action.type) {
    case 'loading':
      return initialPageDataState;
    case 'success':
      return { status: 'success', data: action.data, error: null };
    case 'error':
      return { status: 'error', data: null, error: action.error };
    default:
      return state;
  }
}

export function createPageDataLoader(load, dispatch) {
  let requestId = 0;
  let inFlight = false;

  return {
    async retry() {
      if (inFlight) return;
      inFlight = true;
      const currentRequest = ++requestId;
      dispatch({ type: 'loading' });

      try {
        const data = await load();
        if (currentRequest === requestId) dispatch({ type: 'success', data });
      } catch (error) {
        if (currentRequest === requestId) dispatch({ type: 'error', error });
      } finally {
        if (currentRequest === requestId) inFlight = false;
      }
    },

    cancel() {
      requestId++;
      inFlight = false;
    },
  };
}

export function schedulePageDataLoad(loader) {
  let active = true;
  queueMicrotask(() => {
    if (active) loader.retry();
  });

  return () => {
    active = false;
    loader.cancel();
  };
}

export default function usePageData(load) {
  const [state, dispatch] = useReducer(pageDataReducer, initialPageDataState);
  const loader = useMemo(() => createPageDataLoader(load, dispatch), [load]);

  useEffect(() => schedulePageDataLoad(loader), [loader]);

  return { ...state, retry: loader.retry };
}
