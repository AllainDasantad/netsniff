
import { useMemo, useState } from "react";
import {
  Search,
  Globe,
  ArrowDownLeft,
  ArrowUpRight,
  Network,
  Database,
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


interface HostInfo {
  ip: string;
  sentPackets: number;
  receivedPackets: number;
  totalPackets: number;
  bytes: number;
  protocols: Set<string>;
}

interface IPAnalysisProps {
  packets: PacketInfo[];
}

export default function IPAnalysis({ packets }: IPAnalysisProps) {
  const [search, setSearch] = useState("");

  const hosts = useMemo(() => {
    const hostMap = new Map<string, HostInfo>();

    packets.forEach((packet) => {
      const source = packet.source;
      const destination = packet.destination;

      if (!hostMap.has(source)) {
        hostMap.set(source, {
          ip: source,
          sentPackets: 0,
          receivedPackets: 0,
          totalPackets: 0,
          bytes: 0,
          protocols: new Set(),
        });
      }

      if (!hostMap.has(destination)) {
        hostMap.set(destination, {
          ip: destination,
          sentPackets: 0,
          receivedPackets: 0,
          totalPackets: 0,
          bytes: 0,
          protocols: new Set(),
        });
      }

      const sourceHost = hostMap.get(source)!;
      const destinationHost = hostMap.get(destination)!;

      sourceHost.sentPackets += 1;
      sourceHost.totalPackets += 1;
      sourceHost.bytes += packet.size;
      sourceHost.protocols.add(packet.protocol);

      destinationHost.receivedPackets += 1;
      destinationHost.totalPackets += 1;
      destinationHost.bytes += packet.size;
      destinationHost.protocols.add(packet.protocol);
    });

    return Array.from(hostMap.values()).sort(
      (a, b) => b.bytes - a.bytes
    );
  }, [packets]);

  const filteredHosts = hosts.filter((host) =>
    host.ip.toLowerCase().includes(search.toLowerCase())
  );

  const totalHosts = hosts.length;
  const totalBytes = hosts.reduce((sum, host) => sum + host.bytes, 0);
  const totalSent = hosts.reduce((sum, host) => sum + host.sentPackets, 0);
  const totalReceived = hosts.reduce(
    (sum, host) => sum + host.receivedPackets,
    0
  );

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="ip-analysis-page">
      <div className="ip-analysis-heading">
        <div>
          <h2>IP Analysis</h2>
          <p>Analyze network hosts and their traffic activity.</p>
        </div>

        <div className="ip-analysis-live">
          <span className="live-dot" />
          LIVE DATA
        </div>
      </div>

      <div className="ip-analysis-stats">
        <div className="ip-stat-card">
          <Globe />
          <div>
            <span>Unique Hosts</span>
            <strong>{totalHosts}</strong>
          </div>
        </div>

        <div className="ip-stat-card">
          <ArrowUpRight />
          <div>
            <span>Packets Sent</span>
            <strong>{totalSent.toLocaleString()}</strong>
          </div>
        </div>

        <div className="ip-stat-card">
          <ArrowDownLeft />
          <div>
            <span>Packets Received</span>
            <strong>{totalReceived.toLocaleString()}</strong>
          </div>
        </div>

        <div className="ip-stat-card">
          <Database />
          <div>
            <span>Host Traffic</span>
            <strong>{formatBytes(totalBytes)}</strong>
          </div>
        </div>
      </div>

      <div className="ip-analysis-panel">
        <div className="ip-analysis-toolbar">
          <div>
            <Network size={18} />
            <h3>Network Hosts</h3>
            <span>{filteredHosts.length} hosts</span>
          </div>

          <div className="ip-search">
            <Search size={16} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search IP address..."
            />
          </div>
        </div>

        <div className="ip-table-wrapper">
          <table className="ip-analysis-table">
            <thead>
              <tr>
                <th>IP ADDRESS</th>
                <th>PROTOCOLS</th>
                <th>SENT</th>
                <th>RECEIVED</th>
                <th>TOTAL PACKETS</th>
                <th>TRAFFIC</th>
              </tr>
            </thead>

            <tbody>
              {filteredHosts.map((host) => (
                <tr key={host.ip}>
                  <td>
                    <div className="ip-address-cell">
                      <Globe size={16} />
                      <span>{host.ip}</span>
                    </div>
                  </td>

                  <td>
                    <div className="ip-protocols">
                      {Array.from(host.protocols).map((protocol) => (
                        <span key={protocol}>{protocol}</span>
                      ))}
                    </div>
                  </td>

                  <td>{host.sentPackets.toLocaleString()}</td>
                  <td>{host.receivedPackets.toLocaleString()}</td>
                  <td>{host.totalPackets.toLocaleString()}</td>
                  <td className="ip-traffic">{formatBytes(host.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredHosts.length === 0 && (
            <div className="ip-empty-state">
              <Globe size={32} />
              <p>No IP hosts found</p>
              <span>Start capturing packets or change your search.</span>
            </div>
          )}
        </div>

        <div className="ip-analysis-footer">
          <span>
            Showing {filteredHosts.length} of {totalHosts} hosts
          </span>
          <span>Sorted by traffic volume</span>
        </div>
      </div>
    </div>
  );
}

