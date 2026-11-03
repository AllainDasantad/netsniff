
import { useMemo, useState } from "react";
import {
  Search,
  Network,
  X,
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  FileText,
  Hexagon,
  Shield,
  Globe,
  CircleHelp,
} from "lucide-react";
import type { PacketInfo } from "../types/packet";

interface TCPStream {
  id: string;
  endpointA: string;
  endpointB: string;
  packets: PacketInfo[];
  bytes: number;
  payloadBytes: number;
  firstSeen: string;
  lastSeen: string;
}

interface ProtocolDetection {
  name: string;
  description: string;
  category: "tls" | "http" | "unknown";
}

function endpoint(packet: PacketInfo) {
  return `${packet.source}:${packet.source_port}`;
}

function destination(packet: PacketInfo) {
  return `${packet.destination}:${packet.destination_port}`;
}

function getStreamKey(packet: PacketInfo) {
  return [endpoint(packet), destination(packet)].sort().join(" <-> ");
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function formatTime(timestamp: string) {
  const date = new Date(timestamp);

  return Number.isNaN(date.getTime())
    ? timestamp
    : date.toLocaleTimeString();
}

function timestampValue(timestamp: string) {
  const value = new Date(timestamp).getTime();
  return Number.isNaN(value) ? 0 : value;
}

function getFlags(packet: PacketInfo) {
  return packet.tcp_flags || "-";
}

function flagColor(flag: string) {
  if (flag.includes("SYN")) return "flag-syn";
  if (flag.includes("RST")) return "flag-rst";
  if (flag.includes("FIN")) return "flag-fin";
  if (flag.includes("PSH")) return "flag-psh";
  return "flag-normal";
}

function getPayload(packet: PacketInfo): number[] {
  return packet.payload ?? [];
}

function getAscii(bytes: number[]) {
  return bytes
    .map((byte) =>
      byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : "."
    )
    .join("");
}

function getHexRows(bytes: number[]) {
  const rows = [];

  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);

    const hex = chunk
      .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
      .join(" ")
      .padEnd(47, " ");

    rows.push({
      offset: i.toString(16).padStart(8, "0").toUpperCase(),
      hex,
      ascii: getAscii(chunk),
    });
  }

  return rows;
}

// Identify common HTTP and TLS payload signatures.
function detectProtocol(bytes: number[]): ProtocolDetection {
  if (bytes.length < 1) {
    return {
      name: "No Payload",
      description: "This TCP packet has no application payload.",
      category: "unknown",
    };
  }

  const first = bytes[0];
  const second = bytes[1] ?? 0;
  const third = bytes[2] ?? 0;

  // TLS record content types:
  // 0x14 = Change Cipher Spec
  // 0x15 = Alert
  // 0x16 = Handshake
  // 0x17 = Application Data
  const isTLSContentType = [0x14, 0x15, 0x16, 0x17].includes(first);
  const isTLSVersion =
    second === 0x03 && [0x00, 0x01, 0x02, 0x03, 0x04].includes(third);

  if (isTLSContentType && isTLSVersion && bytes.length >= 5) {
    const recordLength = ((bytes[3] ?? 0) << 8) | (bytes[4] ?? 0);

    const recordNames: Record<number, string> = {
      0x14: "TLS Change Cipher Spec",
      0x15: "TLS Alert",
      0x16: "TLS Handshake",
      0x17: "TLS Application Data",
    };

    const versionNames: Record<string, string> = {
      "03 00": "SSL 3.0",
      "03 01": "TLS 1.0",
      "03 02": "TLS 1.1",
      "03 03": "TLS 1.2 record format",
      "03 04": "TLS 1.3 record format",
    };

    const version = versionNames[
      `${second.toString(16).padStart(2, "0")} ${third
        .toString(16)
        .padStart(2, "0")}`
    ] ?? "Unknown TLS version";

    return {
      name: recordNames[first],
      description: `${version} · Record length: ${recordLength} bytes`,
      category: "tls",
    };
  }

  // Convert the beginning of the payload into readable text.
  const text = getAscii(bytes.slice(0, 32));

  const httpMethods = [
    "GET ",
    "POST ",
    "PUT ",
    "DELETE ",
    "HEAD ",
    "OPTIONS ",
    "PATCH ",
    "CONNECT ",
    "TRACE ",
  ];

  const method = httpMethods.find((item) => text.startsWith(item));

  if (method) {
    return {
      name: `HTTP ${method.trim()}`,
      description: "Recognized HTTP request method.",
      category: "http",
    };
  }

  if (text.startsWith("HTTP/1.0") || text.startsWith("HTTP/1.1")) {
    return {
      name: "HTTP Response",
      description: "Recognized HTTP response status line.",
      category: "http",
    };
  }

  if (text.startsWith("HTTP/2")) {
    return {
      name: "HTTP/2",
      description: "Recognized HTTP/2 text signature.",
      category: "http",
    };
  }

  return {
    name: "Unknown / Other",
    description: "No supported HTTP or TLS signature was detected.",
    category: "unknown",
  };
}

function ProtocolBadge({ detection }: { detection: ProtocolDetection }) {
  const Icon =
    detection.category === "tls"
      ? Shield
      : detection.category === "http"
        ? Globe
        : CircleHelp;

  return (
    <span
      className={`payload-protocol-badge protocol-${detection.category}`}
      title={detection.description}
    >
      <Icon size={13} />
      {detection.name}
    </span>
  );
}

export default function TCPStreams({
  packets,
}: {
  packets: PacketInfo[];
}) {
  const [search, setSearch] = useState("");
  const [selectedStreamId, setSelectedStreamId] = useState<string | null>(
    null
  );
  const [selectedPacket, setSelectedPacket] = useState<PacketInfo | null>(
    null
  );
  const [streamFilter, setStreamFilter] = useState("");
  const [viewMode, setViewMode] = useState<"conversation" | "packets">(
    "conversation"
  );
  const [payloadMode, setPayloadMode] = useState<"hex" | "ascii">("hex");

  const streams = useMemo(() => {
    const grouped = new Map<string, TCPStream>();

    for (const packet of packets) {
      if (packet.protocol.toUpperCase() !== "TCP") continue;

      const key = getStreamKey(packet);

      if (!grouped.has(key)) {
        const endpoints = key.split(" <-> ");

        grouped.set(key, {
          id: key,
          endpointA: endpoints[0],
          endpointB: endpoints[1],
          packets: [],
          bytes: 0,
          payloadBytes: 0,
          firstSeen: packet.timestamp,
          lastSeen: packet.timestamp,
        });
      }

      const stream = grouped.get(key)!;

      stream.packets.push(packet);
      stream.bytes += packet.size;
      stream.payloadBytes += getPayload(packet).length;

      if (
        timestampValue(packet.timestamp) <
        timestampValue(stream.firstSeen)
      ) {
        stream.firstSeen = packet.timestamp;
      }

      if (
        timestampValue(packet.timestamp) >
        timestampValue(stream.lastSeen)
      ) {
        stream.lastSeen = packet.timestamp;
      }
    }

    return Array.from(grouped.values())
      .map((stream) => ({
        ...stream,
        packets: [...stream.packets].sort(
          (a, b) =>
            timestampValue(a.timestamp) - timestampValue(b.timestamp)
        ),
      }))
      .sort((a, b) => b.packets.length - a.packets.length);
  }, [packets]);

  const selectedStream = useMemo(
    () => streams.find((stream) => stream.id === selectedStreamId) ?? null,
    [streams, selectedStreamId]
  );

  const filteredStreams = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) return streams;

    return streams.filter(
      (stream) =>
        stream.endpointA.toLowerCase().includes(query) ||
        stream.endpointB.toLowerCase().includes(query)
    );
  }, [streams, search]);

  const filteredPackets = useMemo(() => {
    if (!selectedStream) return [];

    const query = streamFilter.trim().toLowerCase();

    if (!query) return selectedStream.packets;

    return selectedStream.packets.filter((packet) => {
      const payload = getPayload(packet);
      const payloadText = getAscii(payload);
      const detection = detectProtocol(payload);

      return (
        endpoint(packet).toLowerCase().includes(query) ||
        destination(packet).toLowerCase().includes(query) ||
        packet.protocol.toLowerCase().includes(query) ||
        getFlags(packet).toLowerCase().includes(query) ||
        payloadText.toLowerCase().includes(query) ||
        detection.name.toLowerCase().includes(query)
      );
    });
  }, [selectedStream, streamFilter]);

  const selectedPayload = selectedPacket
    ? getPayload(selectedPacket)
    : [];

  const selectedDetection = detectProtocol(selectedPayload);
  const hexRows = getHexRows(selectedPayload);

  const totalPackets = streams.reduce(
    (sum, stream) => sum + stream.packets.length,
    0
  );

  const totalBytes = streams.reduce(
    (sum, stream) => sum + stream.bytes,
    0
  );

  function openStream(stream: TCPStream) {
    setSelectedStreamId(stream.id);
    setSelectedPacket(null);
    setStreamFilter("");
    setViewMode("conversation");
    setPayloadMode("hex");
  }

  function closeStream() {
    setSelectedStreamId(null);
    setSelectedPacket(null);
    setStreamFilter("");
  }

  function packetDirection(packet: PacketInfo) {
    return endpoint(packet) === selectedStream?.endpointA
      ? "client"
      : "server";
  }

  return (
    <div className="tcp-streams">
      <div className="tcp-streams-header">
        <div>
          <h1>TCP Streams</h1>
          <p>Inspect TCP connections and packet payloads.</p>
        </div>

        <div className="tcp-streams-total">
          <Network size={18} />
          {streams.length} streams
        </div>
      </div>

      <div className="tcp-streams-summary">
        <div className="stream-summary-card">
          <Network />
          <div>
            <span>Total Streams</span>
            <strong>{streams.length}</strong>
          </div>
        </div>

        <div className="stream-summary-card">
          <Activity />
          <div>
            <span>TCP Packets</span>
            <strong>{totalPackets}</strong>
          </div>
        </div>

        <div className="stream-summary-card">
          <FileText />
          <div>
            <span>Total Traffic</span>
            <strong>{formatBytes(totalBytes)}</strong>
          </div>
        </div>
      </div>

      <div className="tcp-streams-toolbar">
        <Search size={18} />
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search IP addresses or ports..."
        />
      </div>

      <div className="tcp-stream-table-wrapper">
        <table className="tcp-stream-table">
          <thead>
            <tr>
              <th>Stream</th>
              <th>Endpoint A</th>
              <th>Endpoint B</th>
              <th>Packets</th>
              <th>Payload</th>
              <th>Bytes</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            {filteredStreams.map((stream, index) => (
              <tr key={stream.id}>
                <td>
                  <span className="stream-number">#{index + 1}</span>
                </td>
                <td>{stream.endpointA}</td>
                <td>{stream.endpointB}</td>
                <td>{stream.packets.length}</td>
                <td>{formatBytes(stream.payloadBytes)}</td>
                <td>{formatBytes(stream.bytes)}</td>
                <td>
                  <button
                    className="stream-open-button"
                    onClick={() => openStream(stream)}
                  >
                    Follow Stream
                  </button>
                </td>
              </tr>
            ))}

            {filteredStreams.length === 0 && (
              <tr>
                <td colSpan={7} className="stream-empty">
                  {streams.length === 0
                    ? "No TCP streams found. Start capturing TCP traffic."
                    : "No streams match your search."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {selectedStream && (
        <div className="tcp-stream-modal-overlay">
          <div className="tcp-stream-modal">
            <div className="tcp-stream-modal-header">
              <div>
                <h2>Follow TCP Stream</h2>
                <p>
                  {selectedStream.endpointA} ↔ {selectedStream.endpointB}
                </p>
                <p>
                  {selectedStream.packets.length} packets ·{" "}
                  {formatBytes(selectedStream.bytes)} ·{" "}
                  {formatBytes(selectedStream.payloadBytes)} payload
                </p>
              </div>

              <button
                className="stream-close-button"
                onClick={closeStream}
                aria-label="Close stream"
              >
                <X size={20} />
              </button>
            </div>

            <div className="tcp-stream-modal-toolbar">
              <div className="stream-view-switch">
                <button
                  className={viewMode === "conversation" ? "active" : ""}
                  onClick={() => {
                    setViewMode("conversation");
                    setSelectedPacket(null);
                  }}
                >
                  Conversation
                </button>

                <button
                  className={viewMode === "packets" ? "active" : ""}
                  onClick={() => {
                    setViewMode("packets");
                    setSelectedPacket(null);
                  }}
                >
                  Packet List
                </button>
              </div>

              <div className="stream-filter">
                <Search size={15} />
                <input
                  value={streamFilter}
                  onChange={(event) => setStreamFilter(event.target.value)}
                  placeholder="Filter IPs, flags, or protocol..."
                />
              </div>
            </div>

            {viewMode === "conversation" ? (
              <div className="stream-conversation">
                {filteredPackets.map((packet, index) => {
                  const direction = packetDirection(packet);
                  const payload = getPayload(packet);
                  const detection = detectProtocol(payload);

                  return (
                    <div
                      key={`${packet.timestamp}-${index}`}
                      className={`conversation-message ${direction}`}
                    >
                      <div className="conversation-message-header">
                        {direction === "client" ? (
                          <ArrowUpRight size={15} />
                        ) : (
                          <ArrowDownLeft size={15} />
                        )}

                        <span>
                          {direction === "client"
                            ? selectedStream.endpointA
                            : selectedStream.endpointB}
                        </span>

                        <span
                          className={`tcp-flag ${flagColor(getFlags(packet))}`}
                        >
                          {getFlags(packet)}
                        </span>

                        <span>{formatTime(packet.timestamp)}</span>
                      </div>

                      <div className="conversation-payload">
                        {payload.length > 0 ? (
                          <pre>{getAscii(payload)}</pre>
                        ) : (
                          <span className="no-payload">
                            No application payload ({getFlags(packet)})
                          </span>
                        )}
                      </div>

                      <div className="conversation-detection">
                        <ProtocolBadge detection={detection} />
                      </div>

                      <button
                        className="inspect-packet-button"
                        onClick={() => {
                          setSelectedPacket(packet);
                          setPayloadMode("hex");
                        }}
                      >
                        Inspect payload · {payload.length} bytes
                      </button>
                    </div>
                  );
                })}

                {filteredPackets.length === 0 && (
                  <div className="stream-empty">
                    No packets match your filter.
                  </div>
                )}
              </div>
            ) : (
              <div className="stream-packet-table-wrapper">
                <table className="stream-packet-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Time</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Flags</th>
                      <th>Detected Protocol</th>
                      <th>Payload</th>
                      <th>Size</th>
                      <th></th>
                    </tr>
                  </thead>

                  <tbody>
                    {filteredPackets.map((packet, index) => {
                      const detection = detectProtocol(getPayload(packet));

                      return (
                        <tr key={`${packet.timestamp}-${index}`}>
                          <td>{index + 1}</td>
                          <td>{formatTime(packet.timestamp)}</td>
                          <td>{endpoint(packet)}</td>
                          <td>{destination(packet)}</td>
                          <td>
                            <span
                              className={`tcp-flag ${flagColor(getFlags(packet))}`}
                            >
                              {getFlags(packet)}
                            </span>
                          </td>
                          <td>
                            <ProtocolBadge detection={detection} />
                          </td>
                          <td>{getPayload(packet).length} B</td>
                          <td>{packet.size} B</td>
                          <td>
                            <button
                              className="inspect-packet-button"
                              onClick={() => {
                                setSelectedPacket(packet);
                                setPayloadMode("hex");
                              }}
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })}

                    {filteredPackets.length === 0 && (
                      <tr>
                        <td colSpan={9} className="stream-empty">
                          No packets match your filter.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {selectedPacket && (
              <div className="payload-inspector">
                <div className="payload-inspector-header">
                  <div>
                    <h3>
                      <Hexagon size={17} />
                      Payload Inspector
                    </h3>
                    <p>
                      {endpoint(selectedPacket)} →{" "}
                      {destination(selectedPacket)}
                    </p>
                  </div>

                  <button
                    className="stream-close-button"
                    onClick={() => setSelectedPacket(null)}
                    aria-label="Close payload inspector"
                  >
                    <X size={18} />
                  </button>
                </div>

                <div className="payload-detection-details">
                  <span>Detected Protocol</span>
                  <ProtocolBadge detection={selectedDetection} />
                  <p>{selectedDetection.description}</p>
                </div>

                <div className="payload-view-switch">
                  <button
                    className={payloadMode === "hex" ? "active" : ""}
                    onClick={() => setPayloadMode("hex")}
                  >
                    Hexadecimal
                  </button>

                  <button
                    className={payloadMode === "ascii" ? "active" : ""}
                    onClick={() => setPayloadMode("ascii")}
                  >
                    ASCII
                  </button>
                </div>

                <div className="payload-viewer">
                  {selectedPayload.length === 0 ? (
                    <div className="stream-empty">
                      This packet has no TCP payload.
                    </div>
                  ) : payloadMode === "hex" ? (
                    <div className="hex-viewer">
                      <div className="hex-viewer-heading">
                        <span>Offset</span>
                        <span>Hexadecimal</span>
                        <span>ASCII</span>
                      </div>

                      {hexRows.map((row) => (
                        <div className="hex-viewer-row" key={row.offset}>
                          <span className="hex-offset">{row.offset}</span>
                          <span className="hex-bytes">{row.hex}</span>
                          <span className="hex-ascii">{row.ascii}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <pre className="ascii-viewer">
                      {getAscii(selectedPayload)}
                    </pre>
                  )}
                </div>

                <div className="payload-inspector-footer">
                  {selectedPayload.length} payload bytes ·{" "}
                  {getFlags(selectedPacket)}
                </div>
              </div>
            )}

            <div className="stream-inspector-note">
              Detection uses packet payload signatures. TLS traffic remains
              encrypted. TCP sequence reassembly is not implemented yet.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

