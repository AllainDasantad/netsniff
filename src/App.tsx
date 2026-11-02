
import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Activity,
  BarChart3,
  FileText,
  Globe,
  LayoutDashboard,
  Network,
  Play,
  Search,
  Settings,
  Square,
  Wifi,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import FeaturesWithPanel from "./components/FeaturesWithPanel";
import GlowCard from "./components/GlowCard";
import PacketExplorer from "./components/PacketExplorer";
import IPAnalysis from "./components/IPAnalysis";
import TCPUDPAnalysis from "./components/TCPUDPAnalysis";
import "./App.css";

export interface PacketInfo {
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  source_port: string;
  destination_port: string;
  size: number;
}

interface CapturePacket {
  timestamp?: string;
  source?: string;
  destination?: string;
  protocol?: string;
  source_port?: string | number | null;
  destination_port?: string | number | null;
  size?: number;
}

const navigation = [
  { name: "Dashboard", icon: LayoutDashboard },
  { name: "Live Capture", icon: Activity },
  { name: "Packet Explorer", icon: Search },
  { name: "IP Analysis", icon: Globe },
  { name: "TCP/UDP Analysis", icon: Network },
  { name: "Traffic Statistics", icon: BarChart3 },
  { name: "Reports", icon: FileText },
  { name: "Settings", icon: Settings },
];

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(2)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function App() {
  const [activePage, setActivePage] = useState("Dashboard");
  const [capturing, setCapturing] = useState(false);
  const [captureError, setCaptureError] = useState("");
  const [capturedPackets, setCapturedPackets] = useState<PacketInfo[]>([]);
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [selectedInterface, setSelectedInterface] = useState("wlan0");
  const [interfaceError, setInterfaceError] = useState("");
  const [search, setSearch] = useState("");

  // Load network interfaces
  useEffect(() => {
    let mounted = true;

    invoke<string[]>("list_interfaces")
      .then((items) => {
        if (!mounted) return;

        setInterfaces(items);

        if (items.length > 0 && !items.includes(selectedInterface)) {
          setSelectedInterface(items[0]);
        }
      })
      .catch((error) => {
        if (mounted) setInterfaceError(String(error));
      });

    return () => {
      mounted = false;
    };
  }, []);

  // Listen for packets and capture events from Rust
  useEffect(() => {
    let unlistenPacket: (() => void) | undefined;
    let unlistenError: (() => void) | undefined;
    let unlistenStopped: (() => void) | undefined;
    let disposed = false;

    const setupListeners = async () => {
      try {
        const packetListener = await listen<CapturePacket>(
          "packet-captured",
          (event) => {
            const packet = event.payload;

            const newPacket: PacketInfo = {
              timestamp:
                packet.timestamp ?? new Date().toISOString(),
              source: packet.source ?? "Unknown",
              destination: packet.destination ?? "Unknown",
              protocol: packet.protocol ?? "Other",
              source_port: String(packet.source_port ?? "-"),
              destination_port: String(
                packet.destination_port ?? "-"
              ),
              size: packet.size ?? 0,
            };

            setCapturedPackets((previous) =>
              [...previous, newPacket].slice(-1000)
            );
          }
        );

        const errorListener = await listen<string>(
          "capture-error",
          (event) => {
            setCaptureError(event.payload);
            setCapturing(false);
          }
        );

        const stoppedListener = await listen(
          "capture-stopped",
          () => {
            setCapturing(false);
          }
        );

        if (disposed) {
          packetListener();
          errorListener();
          stoppedListener();
          return;
        }

        unlistenPacket = packetListener;
        unlistenError = errorListener;
        unlistenStopped = stoppedListener;
      } catch (error) {
        console.error("Failed to initialize capture listeners:", error);
        setCaptureError(String(error));
      }
    };

    setupListeners();

    return () => {
      disposed = true;
      unlistenPacket?.();
      unlistenError?.();
      unlistenStopped?.();
    };
  }, []);

  // Start and stop packet capture
  const handleCapture = async () => {
    setCaptureError("");

    try {
      if (capturing) {
        await invoke("stop_capture");
        setCapturing(false);
        return;
      }

      if (!selectedInterface) {
        setCaptureError("Please select a network interface.");
        return;
      }

      setCapturedPackets([]);

      await invoke("start_capture", {
        interfaceName: selectedInterface,
      });

      setCapturing(true);
      setActivePage("Live Capture");
    } catch (error) {
      setCaptureError(String(error));
      setCapturing(false);
    }
  };

  // Packet statistics
  const totalPackets = capturedPackets.length;

  const totalBytes = capturedPackets.reduce(
    (sum, packet) => sum + packet.size,
    0
  );

  const tcpPackets = capturedPackets.filter(
    (packet) => packet.protocol.toUpperCase() === "TCP"
  );

  const udpPackets = capturedPackets.filter(
    (packet) => packet.protocol.toUpperCase() === "UDP"
  );

  const icmpPackets = capturedPackets.filter(
    (packet) => packet.protocol.toUpperCase() === "ICMP"
  );

  const otherPackets =
    totalPackets -
    tcpPackets.length -
    udpPackets.length -
    icmpPackets.length;

  const protocolData = [
    { name: "TCP", value: tcpPackets.length },
    { name: "UDP", value: udpPackets.length },
    { name: "ICMP", value: icmpPackets.length },
    { name: "Other", value: otherPackets },
  ];

  // Traffic chart
  const trafficData = useMemo(() => {
    const groups = new Map<string, number>();

    capturedPackets.forEach((packet) => {
      const date = new Date(packet.timestamp);

      const label = Number.isNaN(date.getTime())
        ? packet.timestamp
        : date.toLocaleTimeString();

      groups.set(
        label,
        (groups.get(label) ?? 0) + packet.size
      );
    });

    return Array.from(groups.entries())
      .slice(-20)
      .map(([time, bytes]) => ({
        time,
        bytes,
      }));
  }, [capturedPackets]);

  // Dashboard packet search
  const filteredPackets = capturedPackets.filter((packet) =>
    [
      packet.source,
      packet.destination,
      packet.protocol,
      packet.source_port,
      packet.destination_port,
    ]
      .join(" ")
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">
            <Network size={24} />
          </div>

          <div>
            <h2>PSA</h2>
            <span>Network Analyzer</span>
          </div>
        </div>

        <div className="sidebar-section-label">MENU</div>

        <nav className="sidebar-navigation">
          {navigation.map((item) => {
            const Icon = item.icon;

            return (
              <button
                key={item.name}
                className={`nav-item ${
                  activePage === item.name ? "active" : ""
                }`}
                onClick={() => setActivePage(item.name)}
              >
                <Icon size={18} />
                <span>{item.name}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-status">
            <span
              className={`status-dot ${
                capturing ? "online" : ""
              }`}
            />
            {capturing
              ? "Capturing traffic"
              : "Capture stopped"}
          </div>

          <span className="sidebar-version">PSA v0.1.0</span>
        </div>
      </aside>

      {/* Main application */}
      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <span className="topbar-label">
              Network Monitoring
            </span>

            <span className="topbar-divider">/</span>

            <span>{activePage}</span>
          </div>

          <div className="topbar-right">
            <span
              className={`capture-indicator ${
                capturing ? "active" : ""
              }`}
            >
              <span className="status-dot" />
              {capturing ? "LIVE" : "IDLE"}
            </span>
          </div>
        </header>

        <div className="page-content">
          {/* Page heading */}
          <div className="page-heading">
            <div>
              <h1>{activePage}</h1>

              <p>
                {activePage === "Dashboard"
                  ? "Monitor and analyze your network traffic."
                  : `PSA Network Analyzer / ${activePage}`}
              </p>
            </div>

            {/* Capture controls */}
            <div className="capture-controls">
              <select
                value={selectedInterface}
                onChange={(event) =>
                  setSelectedInterface(event.target.value)
                }
                disabled={capturing}
              >
                {interfaces.length === 0 && (
                  <option value="wlan0">wlan0</option>
                )}

                {interfaces.map((networkInterface) => (
                  <option
                    key={networkInterface}
                    value={networkInterface}
                  >
                    {networkInterface}
                  </option>
                ))}
              </select>

              <button
                className={`capture-button ${
                  capturing ? "stop" : "start"
                }`}
                onClick={handleCapture}
              >
                {capturing ? (
                  <Square size={16} />
                ) : (
                  <Play size={16} />
                )}

                {capturing
                  ? "Stop Capture"
                  : "Start Capture"}
              </button>
            </div>
          </div>

          {/* Errors */}
          {(captureError || interfaceError) && (
            <div className="error-banner">
              {captureError || interfaceError}
            </div>
          )}

          {/* Packet Explorer */}
          {activePage === "Packet Explorer" ? (
            <PacketExplorer packets={capturedPackets} />
          ) : activePage === "IP Analysis" ? (
            <IPAnalysis packets={capturedPackets} />
          ) : activePage === "TCP/UDP Analysis" ? (
            <TCPUDPAnalysis packets={capturedPackets} />
          ) : activePage === "Traffic Statistics" ? (
            /* Traffic Statistics */
            <div className="dashboard-grid">
              <GlowCard>
                <div className="stat-card">
                  <span>Total Packets</span>
                  <h2>{totalPackets.toLocaleString()}</h2>
                  <Activity size={20} />
                </div>
              </GlowCard>

              <GlowCard>
                <div className="stat-card">
                  <span>Total Traffic</span>
                  <h2>{formatBytes(totalBytes)}</h2>
                  <Wifi size={20} />
                </div>
              </GlowCard>

              <GlowCard>
                <div className="stat-card">
                  <span>TCP Packets</span>
                  <h2>{tcpPackets.length.toLocaleString()}</h2>
                  <Network size={20} />
                </div>
              </GlowCard>

              <GlowCard>
                <div className="stat-card">
                  <span>UDP Packets</span>
                  <h2>{udpPackets.length.toLocaleString()}</h2>
                  <Globe size={20} />
                </div>
              </GlowCard>

              <GlowCard>
                <h3>Traffic Volume</h3>

                <div style={{ height: 300 }}>
                  <ResponsiveContainer
                    width="100%"
                    height="100%"
                  >
                    <AreaChart data={trafficData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" />
                      <YAxis />
                      <Tooltip />

                      <Area
                        type="monotone"
                        dataKey="bytes"
                        stroke="#6366f1"
                        fill="#6366f1"
                        fillOpacity={0.2}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </GlowCard>
            </div>
          ) : activePage === "Reports" ? (
            /* Reports */
            <GlowCard>
              <h2>Reports</h2>

              <p>
                Captured packets: {totalPackets}.
                Total traffic: {formatBytes(totalBytes)}.
              </p>

              <p>
                Report export functionality can be added here.
              </p>
            </GlowCard>
          ) : activePage === "Settings" ? (
            /* Settings */
            <GlowCard>
              <h2>Settings</h2>

              <p>Network interface: {selectedInterface}</p>

              <p>Maximum stored packets: 1000</p>

              <p>
                Capture status:{" "}
                {capturing ? "Running" : "Stopped"}
              </p>
            </GlowCard>
          ) : (
            /* Dashboard and Live Capture */
            <>
              <div className="dashboard-grid">
                <GlowCard>
                  <div className="stat-card">
                    <span>Total Packets</span>
                    <h2>{totalPackets.toLocaleString()}</h2>
                    <Activity size={20} />
                  </div>
                </GlowCard>

                <GlowCard>
                  <div className="stat-card">
                    <span>Total Traffic</span>
                    <h2>{formatBytes(totalBytes)}</h2>
                    <Wifi size={20} />
                  </div>
                </GlowCard>

                <GlowCard>
                  <div className="stat-card">
                    <span>TCP Packets</span>
                    <h2>{tcpPackets.length.toLocaleString()}</h2>
                    <Network size={20} />
                  </div>
                </GlowCard>

                <GlowCard>
                  <div className="stat-card">
                    <span>UDP Packets</span>
                    <h2>{udpPackets.length.toLocaleString()}</h2>
                    <Globe size={20} />
                  </div>
                </GlowCard>
              </div>

              <div className="dashboard-grid">
                <GlowCard>
                  <h3>Traffic Volume</h3>

                  <div style={{ height: 280 }}>
                    <ResponsiveContainer
                      width="100%"
                      height="100%"
                    >
                      <AreaChart data={trafficData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="time" />
                        <YAxis />
                        <Tooltip />

                        <Area
                          type="monotone"
                          dataKey="bytes"
                          stroke="#6366f1"
                          fill="#6366f1"
                          fillOpacity={0.2}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </GlowCard>

                <GlowCard>
                  <h3>Protocol Summary</h3>

                  <div className="protocol-list">
                    {protocolData.map((item) => (
                      <div
                        className="protocol-row"
                        key={item.name}
                      >
                        <span>{item.name}</span>
                        <strong>{item.value}</strong>
                      </div>
                    ))}
                  </div>
                </GlowCard>
              </div>

              <GlowCard>
                <div className="section-heading">
                  <h3>Recent Packets</h3>

                  <button
                    onClick={() =>
                      setActivePage("Packet Explorer")
                    }
                  >
                    View All
                  </button>
                </div>

                <div className="table-search">
                  <Search size={16} />

                  <input
                    value={search}
                    onChange={(event) =>
                      setSearch(event.target.value)
                    }
                    placeholder="Search IP, protocol, or port..."
                  />
                </div>

                <div className="table-wrapper">
                  <table>
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Protocol</th>
                        <th>Size</th>
                      </tr>
                    </thead>

                    <tbody>
                      {filteredPackets
                        .slice(-10)
                        .reverse()
                        .map((packet, index) => (
                          <tr
                            key={`${packet.timestamp}-${index}`}
                          >
                            <td>{packet.timestamp}</td>
                            <td>{packet.source}</td>
                            <td>{packet.destination}</td>
                            <td>{packet.protocol}</td>
                            <td>{formatBytes(packet.size)}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </GlowCard>

              <FeaturesWithPanel />
            </>
          )}
        </div>
      </main>
    </div>
  );
}

