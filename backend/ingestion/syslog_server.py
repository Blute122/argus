"""Syslog listeners (UDP + TCP) that feed the ingestion pipeline."""

import asyncio

from backend.config import settings
from backend.ingestion.parsers import parse as parse_raw
from backend.ingestion.pipeline import ingest_event


async def _handle_line(raw, src_ip, tenant_id):
    parsed = parse_raw(raw, source_type="syslog")
    if not parsed:
        return
    if src_ip:
        parsed.setdefault("source_ip", src_ip)
    await ingest_event(parsed, ingest_source="syslog", tenant_id=tenant_id)


class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    def datagram_received(self, data, addr):
        src_ip = addr[0] if addr else None
        asyncio.create_task(_handle_line(data, src_ip, self.tenant_id))


class SyslogListeners:
    """Owns the UDP transport + TCP server so they can be closed on shutdown."""

    def __init__(self):
        self._udp_transport = None
        self._tcp_server = None

    async def start(self):
        loop = asyncio.get_running_loop()
        tenant = settings.default_tenant

        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogUDPProtocol(tenant),
            local_addr=(settings.syslog_host, settings.syslog_udp_port),
        )

        async def handle_tcp(reader, writer):
            peer = writer.get_extra_info("peername")
            src_ip = peer[0] if peer else None
            try:
                while True:
                    line = await reader.readline()
                    if not line:
                        break
                    await _handle_line(line, src_ip, tenant)
            finally:
                writer.close()

        self._tcp_server = await asyncio.start_server(
            handle_tcp, settings.syslog_host, settings.syslog_tcp_port
        )
        print(f"[SOC] Syslog listening on {settings.syslog_host} "
              f"udp/{settings.syslog_udp_port} tcp/{settings.syslog_tcp_port}")

    async def stop(self):
        if self._udp_transport:
            self._udp_transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
