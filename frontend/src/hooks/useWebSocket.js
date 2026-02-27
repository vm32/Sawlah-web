import { useEffect, useRef, useCallback, useState } from "react";

export default function useWebSocket(taskId) {
  const wsRef = useRef(null);
  const [output, setOutput] = useState("");
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);

  const connect = useCallback(
    (tid) => {
      const id = tid || taskId;
      if (!id) return;

      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const url = `${protocol}//${window.location.host}/api/tools/ws/${id}`;

      if (wsRef.current) {
        wsRef.current.close();
      }

      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        setDone(true);
      };
      ws.onerror = () => setConnected(false);
      ws.onmessage = (event) => {
        setOutput((prev) => prev + event.data);
      };
    },
    [taskId]
  );

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  const reset = useCallback(() => {
    setOutput("");
    setDone(false);
    setConnected(false);
  }, []);

  useEffect(() => {
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  return { output, connected, done, connect, disconnect, reset };
}
