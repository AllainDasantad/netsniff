
import { useMemo, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  Network,
  Search,
  Wifi,
} from "lucide-react";

interface PacketInfo {
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  source_port: string | number | null;
  destination_port: string | number | null;
  size: number;
}

interface TCPUDPAnalysisProps {
  packets: PacketInfo[];
}

export default function TCPUDPAnalysis({
  packets,
}: TCPUDPAnalysisProps) {
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [search, setSearch] = useState("");

  const transportPackets = useMemo(
    () =>
      packets.filter((packet) =>
        ["TCP", "UDP"].includes(packet.protocol.toUpperCase())
      ),
    [packets]
  );

  const tcpPackets = transportPackets.filter(
    (packet) => packet.protocol.toUpperCase() === "TCP"
  );

  const udpPackets = transportPackets.filter(
    (packet) => packet.protocol.toUpperCase() === "UDP"
  );

  const tcpBytes = tcpPackets.reduce(
    (total, packet) => total + packet.size,
    0
  );

  const udpBytes = udpPackets.reduce(
    (total, packet) => total + packet.size,
    0
  );

  const filteredPackets = useMemo(() => {
    return transportPackets.filter((packet) => {
      const protocol = packet.protocol.toUpperCase();

      const matchesProtocol =
        protocolFilter === "ALL" || protocol === protocolFilter;

      const matchesSearch =
        packet.source.toLowerCase().includes(search.toLowerCase()) ||
        packet.destination.toLowerCase().includes(search.toLowerCase()) ||
        String(packet.source_port ?? "").includes(search) ||
        String(packet.destination_port ?? "").includes(search);

      return matchesProtocol && matchesSearch;
    });
  }, [transportPackets, protocolFilter, search]);

  const portStats = useMemo(() => {
    const map = new Map<
      string,
      { port: string; protocol: string; packets: number; bytes: number }
    >();

    transportPackets.forEach((packet) => {
      const protocol = packet.protocol.toUpperCase();

      const ports = [
        packet.source_port,
        packet.destination_port,
      ];

      ports.forEach((value) => {
        if (value === null || value === undefined || value === "") return;

        const port = String(value);
        const key = `${protocol}-${port}`;

        const current = map.get(key) ?? {
          port,
          protocol,
          packets: 0,
          bytes: 0,
        };

        current.packets += 1;
        current.bytes += packet.size;

        map.set(key, current);
      });
    });

    return Array.from(map.values()).sort(
      (a, b) => b.packets - a.packets
    );
  }, [transportPackets]);

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024)
      return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const tcpPercentage =
    transportPackets.length > 0
      ? (tcpPackets.length / transportPackets.length) * 100
      : 0;

  const udpPercentage =
    transportPackets.length > 0
      ? (udpPackets.length / transportPackets.length) * 100
      : 0;

  return (
    <div className="tcpudp-page">
      <div className="tcpudp-heading">
        <div>
          <h2>TCP / UDP Analysis</h2>
          <p>Transport protocol traffic and port analysis</p>
        </div>

        <div className="tcpudp-live">
          <span className="tcpudp-live-dot" />
          Live Dataset
        </div>
      </div>

      <div className="tcpudp-stats">
        <div className="tcpudp-stat-card tcp">
          <div className="tcpudp-stat-icon">
            <Network size={20} />
          </div>
          <span>TCP Packets</span>
          <h2>{tcpPackets.length.toLocaleString()}</h2>
          <small>{tcpPercentage.toFixed(1)}% of TCP/UDP traffic</small>
        </div>

        <div className="tcpudp-stat-card udp">
          <div className="tcpudp-stat-icon">
            <Wifi size={20} />
          </div>
          <span>UDP Packets</span>
          <h2>{udpPackets.length.toLocaleString()}</h2>
          <small>{udpPercentage.toFixed(1)}% of TCP/UDP traffic</small>
        </div>

        <div className="tcpudp-stat-card">
          <div className="tcpudp-stat-icon">
            <ArrowUpFromLine size={20} />
          </div>
          <span>TCP Traffic</span>
          <h2>{formatBytes(tcpBytes)}</h2>
          <small>Captured TCP bytes</small>
        </div>

        <div className="tcpudp-stat-card">
          <div className="tcpudp-stat-icon">
            <ArrowDownToLine size={20} />
          </div>
          <span>UDP Traffic</span>
          <h2>{formatBytes(udpBytes)}</h2>
          <small>Captured UDP bytes</small>
        </div>
      </div>

      <div className="tcpudp-panel">
        <div className="tcpudp-panel-heading">
          <div>
            <h3>Protocol Distribution</h3>
            <p>TCP vs UDP packet share</p>
          </div>
          <Activity size={20} />
        </div>

        <div className="tcpudp-distribution">
          <div className="tcpudp-distribution-label">
            <span>TCP</span>
            <strong>{tcpPercentage.toFixed(1)}%</strong>
          </div>
          <div className="tcpudp-progress">
            <div
              className="tcpudp-progress-tcp"
              style={{ width: `${tcpPercentage}%` }}
            />
          </div>

          <div className="tcpudp-distribution-label">
            <span>UDP</span>
            <strong>{udpPercentage.toFixed(1)}%</strong>
          </div>
          <div className="tcpudp-progress">
            <div
              className="tcpudp-progress-udp"
              style={{ width: `${udpPercentage}%` }}
            />
          </div>
        </div>
      </div>

      <div className="tcpudp-panel">
        <div className="tcpudp-panel-heading">
          <div>
            <h3>Port Analysis</h3>
            <p>Most active ports in captured traffic</p>
          </div>
        </div>

        <div className="tcpudp-table-wrapper">
          <table className="tcpudp-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Packets</th>
                <th>Traffic</th>
              </tr>
            </thead>
            <tbody>
              {portStats.slice(0, 10).map((port, index) => (
                <tr key={`${port.protocol}-${port.port}-${index}`}>
                  <td className="tcpudp-port">{port.port}</td>
                  <td>
                    <span
                      className={`tcpudp-badge ${port.protocol.toLowerCase()}`}
                    >
                      {port.protocol}
                    </span>
                  </td>
                  <td>{port.packets.toLocaleString()}</td>
                  <td>{formatBytes(port.bytes)}</td>
                </tr>
              ))}

              {portStats.length === 0 && (
                <tr>
                  <td colSpan={4} className="tcpudp-empty">
                    No TCP/UDP ports available yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="tcpudp-panel">
        <div className="tcpudp-panel-heading">
          <div>
            <h3>Transport Packets</h3>
            <p>{filteredPackets.length} packets displayed</p>
          </div>
        </div>

        <div className="tcpudp-toolbar">
          <div className="tcpudp-search">
            <Search size={16} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search IP address or port..."
            />
          </div>

          <select
            value={protocolFilter}
            onChange={(event) => setProtocolFilter(event.target.value)}
          >
            <option value="ALL">All protocols</option>
            <option value="TCP">TCP only</option>
            <option value="UDP">UDP only</option>
          </select>
        </div>

        <div className="tcpudp-table-wrapper">
          <table className="tcpudp-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Protocol</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Src Port</th>
                <th>Dst Port</th>
                <th>Size</th>
              </tr>
            </thead>

            <tbody>
              {filteredPackets.slice(-100).reverse().map((packet, index) => (
                <tr key={`${packet.timestamp}-${index}`}>
                  <td>{packet.timestamp}</td>
                  <td>
                    <span
                      className={`tcpudp-badge ${packet.protocol.toLowerCase()}`}
                    >
                      {packet.protocol}
                    </span>
                  </td>
                  <td>{packet.source}</td>
                  <td>{packet.destination}</td>
                  <td>{packet.source_port ?? "-"}</td>
                  <td>{packet.destination_port ?? "-"}</td>
                  <td>{formatBytes(packet.size)}</td>
                </tr>
              ))}

              {filteredPackets.length === 0 && (
                <tr>
                  <td colSpan={7} className="tcpudp-empty">
                    No matching TCP/UDP packets.
                    Start capture to collect traffic.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="tcpudp-footer">
          Showing latest 100 matching packets
        </div>
      </div>
    </div>
  );
}

