import { useEffect, useRef, useCallback, useState } from 'react';

type WSMessage = {
  type: string;
  data: any;
};

type UseWebSocketOptions = {
  onMessage?: (msg: WSMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  autoReconnect?: boolean;
  reconnectInterval?: number;
  enabled?: boolean;
  requireAuth?: boolean;
};

export function useWebSocket(channel: string, options: UseWebSocketOptions = {}) {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const closedByCleanup = useRef(false);
  const {
    onMessage,
    onConnect,
    onDisconnect,
    autoReconnect = true,
    reconnectInterval = 3000,
    enabled = true,
    requireAuth = true,
  } = options;

  const shouldConnect = useCallback(() => {
    const hasToken = Boolean(localStorage.getItem('soc_token'));
    const isLoginRoute = window.location.hash.includes('/login');
    return enabled && !isLoginRoute && (!requireAuth || hasToken);
  }, [enabled, requireAuth]);

  const connect = useCallback(() => {
    if (!shouldConnect()) {
      setConnected(false);
      return;
    }

    try {
      closedByCleanup.current = false;
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const host =
        window.location.port === '5173'
          ? `${window.location.hostname}:8000`
          : window.location.host;
      const ws = new WebSocket(`${protocol}://${host}/ws/${channel}`);

      ws.onopen = () => {
        setConnected(true);
        onConnect?.();
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data) as WSMessage;
          onMessage?.(msg);
        } catch {}
      };

      ws.onclose = () => {
        setConnected(false);
        onDisconnect?.();
        if (!closedByCleanup.current && autoReconnect && shouldConnect()) {
          reconnectTimer.current = setTimeout(connect, reconnectInterval);
        }
      };

      ws.onerror = () => ws.close();

      wsRef.current = ws;
    } catch {}
  }, [channel, onMessage, onConnect, onDisconnect, autoReconnect, reconnectInterval, shouldConnect]);

  useEffect(() => {
    connect();
    return () => {
      closedByCleanup.current = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [connect]);

  useEffect(() => {
    const closeSocket = () => {
      closedByCleanup.current = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
      wsRef.current = null;
      setConnected(false);
    };

    window.addEventListener('soc:logout', closeSocket);
    return () => window.removeEventListener('soc:logout', closeSocket);
  }, []);

  return { connected, ws: wsRef };
}
