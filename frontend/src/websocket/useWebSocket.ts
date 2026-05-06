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
};

export function useWebSocket(channel: string, options: UseWebSocketOptions = {}) {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const reconnectTimer = useRef<any>(null);
  const { onMessage, onConnect, onDisconnect, autoReconnect = true, reconnectInterval = 3000 } = options;

  const connect = useCallback(() => {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const host = window.location.host;
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
        if (autoReconnect) {
          reconnectTimer.current = setTimeout(connect, reconnectInterval);
        }
      };

      ws.onerror = () => ws.close();

      wsRef.current = ws;
    } catch {}
  }, [channel, onMessage, onConnect, onDisconnect, autoReconnect, reconnectInterval]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { connected, ws: wsRef };
}
