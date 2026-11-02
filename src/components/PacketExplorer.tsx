import { useMemo, useState } from "react";
import {
  Search,
  Activity,
  ArrowDownRight,
  X,
} from "lucide-react";
import type { PacketInfo } from "../App";

interface Props {
  packets: PacketInfo[];
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function protocolClass(protocol: string) {
  return protocol.toLowerCase();
}

export default function PacketExplorer({ packets }: Props) {
  const [search, setSearch] = useState("");
  const [protocol, setProtocol] = useState("ALL");
  const [selectedPacket, setSelectedPacket] = useState<PacketInfo | null>(
    null
  );

  const filteredPackets = useMemo(() => {
    return packets.filter((packet) => {
      const matchesProtocol =
        protocol === "ALL" ||
        packet.protocol.toUpperCase() === protocol;

      const matchesSearch = [
        packet.timestamp,
        packet.source,
        packet.destination,
        packet.protocol,
        packet.source_port,
        packet.destination_port,
        packet.size,
      ]
        .join(" ")
        .toLowerCase()
        .includes(search.toLowerCase());

      return matchesProtocol && matchesSearch;
    });
  }, [packets, search, protocol]);

  const totalBytes = filteredPackets.reduce(
    (total, packet) => total + packet.size,
    0
  );

  return (
    <div className="packet-explorer">
      <div className="packet-explorer-header">
        <div>
          <h2>Live Packet Explorer</h2>
          <p>Inspect captured network packets in real time.</p>
        </div>

        <div className="packet-live-indicator">
          <span className="status-dot online" />
          LIVE DATA
        </div>
      </div>

      <div className="packet-summary">
        <div>
          <Activity size={18} />
          <span>Packets</span>
          <strong>{filteredPackets.length.toLocaleString()}</strong>
        </div>

        <div>
          <ArrowDownRight size={18} />
          <span>Traffic</span>
          <strong>{formatBytes(totalBytes)}</strong>
        </div>
      </div>

      <div className="packet-toolbar">
        <div className="packet-search">
          <Search size={17} />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search IP, protocol, or port..."
          />

          {search && (
            <button onClick={() => setSearch("")}>
              <X size={15} />
            </button>
          )}
        </div>

        <select
          value={protocol}
          onChange={(event) => setProtocol(event.target.value)}
        >
          <option value="ALL">All Protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="ICMP">ICMP</option>
          <option value="OTHER">Other</option>
        </select>
      </div>

      <div className="packet-table-container">
        <table className="packet-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Source Port</th>
              <th>Destination Port</th>
              <th>Length</th>
            </tr>
          </thead>

          <tbody>
            {filteredPackets.slice().reverse().map((packet, index) => (
              <tr
                key={`${packet.timestamp}-${index}`}
                onClick={() => setSelectedPacket(packet)}
                className="packet-row"
              >
                <td className="packet-time">
                  {packet.timestamp}
                </td>

                <td>{packet.source}</td>

                <td>{packet.destination}</td>

                <td>
                  <span
                    className={`protocol-badge ${protocolClass(
                      packet.protocol
                    )}`}
                  >
                    {packet.protocol}
                  </span>
                </td>

                <td>{packet.source_port || "-"}</td>

                <td>{packet.destination_port || "-"}</td>

                <td>{formatBytes(packet.size)}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredPackets.length === 0 && (
          <div className="packet-empty">
            <Activity size={32} />
            <h3>No packets found</h3>
            <p>Start capture or adjust your search filters.</p>
          </div>
        )}
      </div>

      {selectedPacket && (
        <div
          className="packet-modal-overlay"
          onClick={() => setSelectedPacket(null)}
        >
          <div
            className="packet-modal"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="packet-modal-header">
              <h3>Packet Details</h3>

              <button onClick={() => setSelectedPacket(null)}>
                <X size={18} />
              </button>
            </div>

            <div className="packet-details">
              <div>
                <span>Timestamp</span>
                <strong>{selectedPacket.timestamp}</strong>
              </div>

              <div>
                <span>Source IP</span>
                <strong>{selectedPacket.source}</strong>
              </div>

              <div>
                <span>Destination IP</span>
                <strong>{selectedPacket.destination}</strong>
              </div>

              <div>
                <span>Protocol</span>
                <strong>{selectedPacket.protocol}</strong>
              </div>

              <div>
                <span>Source Port</span>
                <strong>{selectedPacket.source_port || "-"}</strong>
              </div>

              <div>
                <span>Destination Port</span>
                <strong>{selectedPacket.destination_port || "-"}</strong>
              </div>

              <div>
                <span>Packet Size</span>
                <strong>{formatBytes(selectedPacket.size)}</strong>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

