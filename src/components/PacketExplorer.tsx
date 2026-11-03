
import { useMemo, useState } from "react";
import {
  Search,
  Activity,
  ArrowDownRight,
  X,
  Copy,
  ChevronRight,
  ChevronDown,
} from "lucide-react";
import type { PacketInfo } from "../types/packet";

interface Props {
  packets: PacketInfo[];
}

interface Field {
  name: string;
  value: string;
  detail?: string;
}

interface Section {
  title: string;
  fields: Field[];
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatTime(timestamp: string) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? timestamp
    : date.toLocaleTimeString();
}

function protocolClass(protocol: string) {
  return protocol.toLowerCase();
}

function read16(data: number[], offset: number) {
  return (data[offset] << 8) | data[offset + 1];
}

function read32(data: number[], offset: number) {
  return (
    data[offset] * 0x1000000 +
    data[offset + 1] * 0x10000 +
    data[offset + 2] * 0x100 +
    data[offset + 3]
  );
}

function macAddress(data: number[], offset: number) {
  return data
    .slice(offset, offset + 6)
    .map((byte: number) => byte.toString(16).padStart(2, "0"))
    .join(":")
    .toUpperCase();
}

function ipv4Address(data: number[], offset: number) {
  return data.slice(offset, offset + 4).join(".");
}

function ipv6Address(data: number[], offset: number) {
  const groups: string[] = [];

  for (let i = 0; i < 16; i += 2) {
    groups.push(
      ((data[offset + i] << 8) | data[offset + i + 1])
        .toString(16)
        .padStart(4, "0")
    );
  }

  return groups.join(":");
}

function dissectPacket(data: number[]): Section[] {
  const sections: Section[] = [];

  if (data.length < 14) {
    return [
      {
        title: "Packet",
        fields: [
          {
            name: "Frame length",
            value: `${data.length} bytes`,
          },
          {
            name: "Status",
            value: "Incomplete Ethernet frame",
          },
        ],
      },
    ];
  }

  const ethertype = read16(data, 12);
  const ethernetFields: Field[] = [
    { name: "Destination MAC", value: macAddress(data, 0) },
    { name: "Source MAC", value: macAddress(data, 6) },
    {
      name: "EtherType",
      value: `0x${ethertype.toString(16).padStart(4, "0")}`,
      detail:
        ethertype === 0x0800
          ? "IPv4"
          : ethertype === 0x86dd
          ? "IPv6"
          : ethertype === 0x0806
          ? "ARP"
          : "Unknown",
    },
  ];

  sections.push({
    title: "Ethernet II",
    fields: ethernetFields,
  });

  let transportOffset = 0;
  let transportProtocol = 0;
  let networkEnd = data.length;

  // IPv4
  if (ethertype === 0x0800 && data.length >= 34) {
    const ip = 14;
    const version = data[ip] >> 4;
    const ihl = (data[ip] & 0x0f) * 4;
    const totalLength = read16(data, ip + 2);
    const flagsFragment = read16(data, ip + 6);
    const protocol = data[ip + 9];

    networkEnd = Math.min(data.length, ip + totalLength);
    transportOffset = ip + ihl;
    transportProtocol = protocol;

    sections.push({
      title: "Internet Protocol Version 4",
      fields: [
        { name: "Version", value: String(version) },
        { name: "Header Length", value: `${ihl} bytes` },
        { name: "Differentiated Services", value: `0x${data[ip + 1].toString(16)}` },
        { name: "Total Length", value: `${totalLength} bytes` },
        { name: "Identification", value: `0x${read16(data, ip + 4).toString(16)}` },
        { name: "Flags", value: `0x${(flagsFragment >> 13).toString(16)}` },
        { name: "Fragment Offset", value: String(flagsFragment & 0x1fff) },
        { name: "TTL", value: String(data[ip + 8]) },
        {
          name: "Protocol",
          value: String(protocol),
          detail:
            protocol === 6
              ? "TCP"
              : protocol === 17
              ? "UDP"
              : protocol === 1
              ? "ICMP"
              : "Other",
        },
        { name: "Header Checksum", value: `0x${read16(data, ip + 10).toString(16)}` },
        { name: "Source Address", value: ipv4Address(data, ip + 12) },
        { name: "Destination Address", value: ipv4Address(data, ip + 16) },
      ],
    });
  }

  // IPv6
  else if (ethertype === 0x86dd && data.length >= 54) {
    const ip = 14;
    const version = data[ip] >> 4;
    const payloadLength = read16(data, ip + 4);
    const nextHeader = data[ip + 6];

    transportOffset = ip + 40;
    transportProtocol = nextHeader;
    networkEnd = Math.min(data.length, transportOffset + payloadLength);

    sections.push({
      title: "Internet Protocol Version 6",
      fields: [
        { name: "Version", value: String(version) },
        { name: "Traffic Class", value: String(((data[ip] & 0x0f) << 4) | (data[ip + 1] >> 4)) },
        { name: "Flow Label", value: `0x${(((data[ip + 1] & 0x0f) << 16) | (data[ip + 2] << 8) | data[ip + 3]).toString(16)}` },
        { name: "Payload Length", value: `${payloadLength} bytes` },
        {
          name: "Next Header",
          value: String(nextHeader),
          detail: nextHeader === 6 ? "TCP" : nextHeader === 17 ? "UDP" : nextHeader === 58 ? "ICMPv6" : "Other",
        },
        { name: "Hop Limit", value: String(data[ip + 7]) },
        { name: "Source Address", value: ipv6Address(data, ip + 8) },
        { name: "Destination Address", value: ipv6Address(data, ip + 24) },
      ],
    });
  }

  // TCP
  if (transportProtocol === 6 && data.length >= transportOffset + 20) {
    const tcp = transportOffset;
    const dataOffset = (data[tcp + 12] >> 4) * 4;
    const flags = data[tcp + 13];

    const flagNames = [
      ["FIN", 0x01],
      ["SYN", 0x02],
      ["RST", 0x04],
      ["PSH", 0x08],
      ["ACK", 0x10],
      ["URG", 0x20],
      ["ECE", 0x40],
      ["CWR", 0x80],
    ];

    sections.push({
      title: "Transmission Control Protocol",
      fields: [
        { name: "Source Port", value: String(read16(data, tcp)) },
        { name: "Destination Port", value: String(read16(data, tcp + 2)) },
        { name: "Sequence Number", value: String(read32(data, tcp + 4)) },
        { name: "Acknowledgment Number", value: String(read32(data, tcp + 8)) },
        { name: "Header Length", value: `${dataOffset} bytes` },
        {
          name: "Flags",
          value: flagNames
            .filter(([, mask]) => (flags & Number(mask)) !== 0)
            .map(([name]) => name)
            .join(", ") || "None",
        },
        { name: "Window Size", value: String(read16(data, tcp + 14)) },
        { name: "Checksum", value: `0x${read16(data, tcp + 16).toString(16)}` },
        { name: "Urgent Pointer", value: String(read16(data, tcp + 18)) },
      ],
    });

    transportOffset += dataOffset;
  }

  // UDP
  else if (transportProtocol === 17 && data.length >= transportOffset + 8) {
    const udp = transportOffset;
    const udpLength = read16(data, udp + 4);

    sections.push({
      title: "User Datagram Protocol",
      fields: [
        { name: "Source Port", value: String(read16(data, udp)) },
        { name: "Destination Port", value: String(read16(data, udp + 2)) },
        { name: "Length", value: `${udpLength} bytes` },
        { name: "Checksum", value: `0x${read16(data, udp + 6).toString(16)}` },
      ],
    });

    transportOffset += 8;
  }

  const payloadLength = Math.max(0, networkEnd - transportOffset);

  sections.push({
    title: "Packet Payload",
    fields: [
      { name: "Payload Offset", value: String(transportOffset) },
      { name: "Payload Length", value: `${payloadLength} bytes` },
      { name: "Frame Length", value: `${data.length} bytes` },
    ],
  });

  return sections;
}

function getHexDump(data: number[]) {
  const rows: { offset: string; hex: string; ascii: string }[] = [];

  for (let i = 0; i < data.length; i += 16) {
    const chunk = data.slice(i, i + 16);

    rows.push({
      offset: i.toString(16).padStart(8, "0").toUpperCase(),
      hex: chunk
        .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
        .join(" ")
        .padEnd(47, " "),
      ascii: chunk
        .map((byte) =>
          byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : "."
        )
        .join(""),
    });
  }

  return rows;
}

export default function PacketExplorer({ packets }: Props) {
  const [search, setSearch] = useState("");
  const [protocol, setProtocol] = useState("ALL");
  const [selectedPacket, setSelectedPacket] = useState<PacketInfo | null>(null);
  const [detailTab, setDetailTab] = useState<"details" | "dissection" | "hex">("dissection");
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({});

  const filteredPackets = useMemo(() => {
    return packets.filter((packet) => {
      const p = packet.protocol.toUpperCase();
      const matchesProtocol =
        protocol === "ALL" ||
        (protocol === "OTHER"
          ? !["TCP", "UDP", "ICMP", "ICMPV6"].includes(p)
          : p === protocol);

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

  const totalBytes = filteredPackets.reduce((sum, packet) => sum + packet.size, 0);
  const rawData = selectedPacket?.raw_data ?? [];
  const sections = useMemo(() => dissectPacket(rawData), [rawData]);
  const hexDump = useMemo(() => getHexDump(rawData), [rawData]);

  async function copyRawData() {
    if (!selectedPacket) return;

    const hex = rawData
      .map((byte: number) => byte.toString(16).padStart(2, "0"))
      .join(" ");

    await navigator.clipboard.writeText(hex);
  }

  function toggleSection(title: string) {
    setExpandedSections((previous) => ({
      ...previous,
      [title]: !(previous[title] ?? true),
    }));
  }

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
        <div><Activity size={18} /><span>Packets</span><strong>{filteredPackets.length}</strong></div>
        <div><ArrowDownRight size={18} /><span>Traffic</span><strong>{formatBytes(totalBytes)}</strong></div>
      </div>

      <div className="packet-toolbar">
        <div className="packet-search">
          <Search size={17} />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search IP, protocol, or port..." />
          {search && <button onClick={() => setSearch("")}><X size={15} /></button>}
        </div>

        <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
          <option value="ALL">All Protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="ICMP">ICMP</option>
          <option value="ICMPV6">ICMPv6</option>
          <option value="OTHER">Other</option>
        </select>
      </div>

      <div className="packet-table-container">
        <table className="packet-table">
          <thead>
            <tr>
              <th>Timestamp</th><th>Source</th><th>Destination</th>
              <th>Protocol</th><th>Source Port</th><th>Destination Port</th><th>Length</th>
            </tr>
          </thead>
          <tbody>
            {filteredPackets.slice().reverse().map((packet, index) => (
              <tr key={`${packet.timestamp}-${index}`} onClick={() => {
                setSelectedPacket(packet);
                setDetailTab("dissection");
                setExpandedSections({});
              }} className="packet-row">
                <td>{formatTime(packet.timestamp)}</td>
                <td>{packet.source}</td>
                <td>{packet.destination}</td>
                <td><span className={`protocol-badge ${protocolClass(packet.protocol)}`}>{packet.protocol}</span></td>
                <td>{packet.source_port || "-"}</td>
                <td>{packet.destination_port || "-"}</td>
                <td>{formatBytes(packet.size)}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {filteredPackets.length === 0 && (
          <div className="packet-empty"><Activity size={32} /><h3>No packets found</h3><p>Start capture or adjust your search filters.</p></div>
        )}
      </div>

      {selectedPacket && (
        <div className="packet-modal-overlay" onClick={() => setSelectedPacket(null)}>
          <div className="packet-modal packet-inspector-modal" onClick={(e) => e.stopPropagation()}>
            <div className="packet-modal-header">
              <h3>Packet Inspection</h3>
              <button onClick={() => setSelectedPacket(null)}><X size={18} /></button>
            </div>

            <div className="packet-detail-tabs">
              <button className={detailTab === "details" ? "active" : ""} onClick={() => setDetailTab("details")}>Summary</button>
              <button className={detailTab === "dissection" ? "active" : ""} onClick={() => setDetailTab("dissection")}>Dissection</button>
              <button className={detailTab === "hex" ? "active" : ""} onClick={() => setDetailTab("hex")}>Hex Dump</button>
            </div>

            {detailTab === "details" && (
              <div className="packet-details">
                <div><span>Timestamp</span><strong>{selectedPacket.timestamp}</strong></div>
                <div><span>Source IP</span><strong>{selectedPacket.source}</strong></div>
                <div><span>Destination IP</span><strong>{selectedPacket.destination}</strong></div>
                <div><span>Protocol</span><strong>{selectedPacket.protocol}</strong></div>
                <div><span>Source Port</span><strong>{selectedPacket.source_port || "-"}</strong></div>
                <div><span>Destination Port</span><strong>{selectedPacket.destination_port || "-"}</strong></div>
                <div><span>Packet Size</span><strong>{formatBytes(selectedPacket.size)}</strong></div>
                <div><span>Raw Bytes</span><strong>{rawData.length} bytes</strong></div>
              </div>
            )}

            {detailTab === "dissection" && (
              <div className="packet-dissection">
                <div className="dissection-frame-title">
                  <Activity size={16} />
                  Frame {packets.indexOf(selectedPacket) + 1}: {selectedPacket.protocol}, {selectedPacket.size} bytes
                </div>

                {sections.map((section) => {
                  const expanded = expandedSections[section.title] ?? true;
                  return (
                    <div className="dissection-section" key={section.title}>
                      <button className="dissection-section-toggle" onClick={() => toggleSection(section.title)}>
                        {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                        <strong>{section.title}</strong>
                      </button>

                      {expanded && (
                        <div className="dissection-fields">
                          {section.fields.map((field) => (
                            <div className="dissection-field" key={field.name}>
                              <span>{field.name}</span>
                              <strong>{field.value}</strong>
                              {field.detail && <small>{field.detail}</small>}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {detailTab === "hex" && (
              <div className="packet-hex-container">
                <div className="packet-hex-header">
                  <span>Offset</span><span>Hexadecimal</span><span>ASCII</span>
                  <button onClick={copyRawData}><Copy size={15} /> Copy</button>
                </div>
                {hexDump.length ? (
                  <pre className="packet-hex">
                    {hexDump.map((row) => (
                      <div className="packet-hex-row" key={row.offset}>
                        <span className="packet-hex-offset">{row.offset}</span>
                        <span className="packet-hex-bytes">{row.hex}</span>
                        <span className="packet-hex-ascii">{row.ascii}</span>
                      </div>
                    ))}
                  </pre>
                ) : <div className="packet-empty">Raw packet data is unavailable.</div>}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

