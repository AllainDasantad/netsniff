
import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Activity,
  BarChart3,
  Globe,
  LayoutDashboard,
  Network,
  Search,
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

import { ShinyButton } from "./components/ShinyButton";
import GlowCard from "./components/GlowCard";
import PacketExplorer from "./components/PacketExplorer";
import IPAnalysis from "./components/IPAnalysis";
import TCPUDPAnalysis from "./components/TCPUDPAnalysis";
import TCPStreams from "./components/TCPStreams";

import "./App.css";

import type { PacketInfo } from "./types/packet";

type PageName =
  | "Dashboard"
  | "Live Capture"
  | "Packet Explorer"
  | "IP Analysis"
  | "TCP/UDP Analysis"
  | "TCP Streams"
  | "Traffic Statistics"
  | "Reports"
  | "Settings";

const navigation: {
  name: PageName;
  icon: typeof LayoutDashboard;
}[] = [
  { name: "Dashboard", icon: LayoutDashboard },
  { name: "Live Capture", icon: Activity },
  { name: "Packet Explorer", icon: Search },
  { name: "IP Analysis", icon: Globe },
  { name: "TCP/UDP Analysis", icon: Network },
  { name: "TCP Streams", icon: Wifi },
  { name: "Traffic Statistics", icon: BarChart3 },
];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;

  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex++;
  }

  return `${value.toFixed(2)} ${units[unitIndex]}`;
}

function App() {
  const [activePage, setActivePage] = useState<PageName>("Dashboard");
  const [selectedInterface, setSelectedInterface] = useState("wlan0");
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [capturing, setCapturing] = useState(false);
  const [capturedPackets, setCapturedPackets] = useState<PacketInfo[]>([]);
  const [captureError, setCaptureError] = useState("");
  const [interfaceError, setInterfaceError] = useState("");
  const [search, setSearch] = useState("");

  const navigateTo = (page: PageName) => {
    setActivePage(page);
  };

  // Load available network interfaces.
  useEffect(() => {
    let mounted = true;

    const loadInterfaces = async () => {
      try {
        const result = await invoke<string[]>("list_interfaces");

        if (mounted) {
          setInterfaces(result);

          if (result.length > 0 && !result.includes(selectedInterface)) {
            setSelectedInterface(result[0]);
          }
        }
      } catch (error) {
        if (mounted) {
          setInterfaceError(String(error));
        }
      }
    };

    loadInterfaces();

    return () => {
      mounted = false;
    };
  }, []);

  // Listen for packets and capture events from Rust.
  useEffect(() => {
    let unlistenPacket: (() => void) | undefined;
    let unlistenError: (() => void) | undefined;
    let unlistenStopped: (() => void) | undefined;
    let mounted = true;

    const setupListeners = async () => {
      try {
        unlistenPacket = await listen<PacketInfo>(
          "packet-captured",
          (event) => {
            if (!mounted) return;

            setCapturedPackets((previous) => [
              ...previous,
              event.payload,
            ].slice(-1000));
          }
        );

        unlistenError = await listen<string>(
          "capture-error",
          (event) => {
            if (!mounted) return;

            setCaptureError(String(event.payload));
            setCapturing(false);
          }
        );

        unlistenStopped = await listen(
          "capture-stopped",
          () => {
            if (mounted) {
              setCapturing(false);
            }
          }
        );
      } catch (error) {
        if (mounted) {
          setCaptureError(`Event listener error: ${String(error)}`);
        }
      }
    };

    setupListeners();

    return () => {
      mounted = false;
      unlistenPacket?.();
      unlistenError?.();
      unlistenStopped?.();
    };
  }, []);

  // Start or stop packet capture.
  const handleCapture = async () => {
    setCaptureError("");

    try {
      if (capturing) {
        await invoke("stop_capture");
        setCapturing(false);
      } else {
        if (!selectedInterface) {
          setCaptureError("Please select a network interface.");
          return;
        }

        await invoke("start_capture", {
          interfaceName: selectedInterface,
        });

        setCapturing(true);
        setActivePage("Live Capture");
      }
    } catch (error) {
      setCaptureError(String(error));
      setCapturing(false);
    }
  };

  // Packet statistics.
  const totalPackets = capturedPackets.length;

  const totalBytes = useMemo(
    () => capturedPackets.reduce((total, packet) => total + packet.size, 0),
    [capturedPackets]
  );

  const tcpPackets = useMemo(
    () =>
      capturedPackets.filter(
        (packet) => packet.protocol.toUpperCase() === "TCP"
      ),
    [capturedPackets]
  );

  const udpPackets = useMemo(
    () =>
      capturedPackets.filter(
        (packet) => packet.protocol.toUpperCase() === "UDP"
      ),
    [capturedPackets]
  );

  const icmpPackets = useMemo(
    () =>
      capturedPackets.filter((packet) =>
        packet.protocol.toUpperCase().includes("ICMP")
      ),
    [capturedPackets]
  );

  const otherPackets = totalPackets - tcpPackets.length -
    udpPackets.length - icmpPackets.length;

  const protocolData = [
    { name: "TCP", value: tcpPackets.length },
    { name: "UDP", value: udpPackets.length },
    { name: "ICMP", value: icmpPackets.length },
    { name: "Other", value: otherPackets },
  ];

  // Search packets.
  const filteredPackets = useMemo(() => {
    const query = search.toLowerCase().trim();

    if (!query) return capturedPackets;

    return capturedPackets.filter((packet) =>
      [
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
        .includes(query)
    );
  }, [capturedPackets, search]);

  // Prepare traffic chart data.
  const trafficData = useMemo(() => {
    return capturedPackets.slice(-20).map((packet, index) => ({
      packet: index + 1,
      size: packet.size,
    }));
  }, [capturedPackets]);

  const renderTrafficChart = (height: number) => (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={trafficData}>
        <defs>
          <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
          </linearGradient>
        </defs>

        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />

        <XAxis
          dataKey="packet"
          stroke="#94a3b8"
          tick={{ fontSize: 11 }}
        />

        <YAxis
          domain={[0, "auto"]}
          stroke="#94a3b8"
          tick={{ fontSize: 11 }}
        />

        <Tooltip
          contentStyle={{
            background: "#111827",
            border: "1px solid #334155",
            borderRadius: "8px",
            color: "#fff",
          }}
          formatter={(value) => [
            formatBytes(Number(value)),
            "Packet size",
          ]}
        />

        <Area
          type="monotone"
          dataKey="size"
          stroke="#38bdf8"
          strokeWidth={2}
          fill="url(#trafficGradient)"
        />
      </AreaChart>
    </ResponsiveContainer>
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
            <h2>Netsnif</h2>
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
                onClick={() => navigateTo(item.name)}
              >
                <Icon size={18} />
                <span>{item.name}</span>
              </button>
            );
          })}
        </nav>

        {/* Sidebar capture controls */}
        <div className="sidebar-capture-control">
          <label htmlFor="sidebar-interface">
            NETWORK INTERFACE
          </label>

          <select
            id="sidebar-interface"
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
              <option key={networkInterface} value={networkInterface}>
                {networkInterface}
              </option>
            ))}
          </select>

          <ShinyButton
            className="sidebar-shiny-button"
            onClick={handleCapture}
          >
            {capturing ? "Stop Capture" : "Start Capture"}
          </ShinyButton>

          <div className="sidebar-status">
            <span
              className={`status-dot ${capturing ? "online" : ""}`}
            />

            {capturing ? "Capturing traffic" : "Capture stopped"}
          </div>
        </div>

      </aside>

      {/* Main application */}
      <main className="main-content">
        <div className="page-content">
          <div className="page-heading">
            <div>
              <h1>{activePage}</h1>

              <p>
                {activePage === "Dashboard"
                  ? "Monitor and analyze your network traffic."
                  : `Netsnif / ${activePage}`}
              </p>
            </div>
          </div>

          {/* Error messages */}
          {(captureError || interfaceError) && (
            <div className="error-banner">
              {captureError || interfaceError}
            </div>
          )}

          {/* Page content */}
          <div className="page-transition">
            {activePage === "Live Capture" ? (
              <GlowCard>
                <div className="live-capture-controls">
                  <div>
                    <h2>Live Packet Capture</h2>
                    <p>
                      Capture status and traffic information for your
                      selected network interface.
                    </p>
                  </div>

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
                </div>

                <div className="live-capture-summary">
                  <p>
                    Packets captured: {totalPackets.toLocaleString()}
                  </p>

                  <p>Total traffic: {formatBytes(totalBytes)}</p>

                  <p>Interface: {selectedInterface}</p>
                </div>
              </GlowCard>
            ) : activePage === "Packet Explorer" ? (
              <PacketExplorer packets={capturedPackets} />
            ) : activePage === "IP Analysis" ? (
              <IPAnalysis packets={capturedPackets} />
            ) : activePage === "TCP/UDP Analysis" ? (
              <TCPUDPAnalysis packets={capturedPackets} />
            ) : activePage === "TCP Streams" ? (
              <TCPStreams packets={capturedPackets} />
            ) : activePage === "Traffic Statistics" ? (
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
                  {renderTrafficChart(300)}
                </GlowCard>
              </div>
            ) : activePage === "Reports" ? (
              <GlowCard>
                <h2>Reports</h2>
                <p>Captured packets: {totalPackets}.</p>
                <p>Total traffic: {formatBytes(totalBytes)}.</p>
                <p>Report export functionality can be added here.</p>
              </GlowCard>
            ) : activePage === "Settings" ? (
              <GlowCard>
                <h2>Settings</h2>
                <p>Maximum stored packets: 1000</p>
                <p>
                  Capture status: {capturing ? "Running" : "Stopped"}
                </p>
                <p>Selected interface: {selectedInterface}</p>
              </GlowCard>
            ) : (
              <>
                {/* Dashboard statistics */}
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

                {/* Dashboard charts */}
                <div className="dashboard-grid">
                  <GlowCard>
                    <h3>Traffic Volume</h3>
                    {renderTrafficChart(280)}
                  </GlowCard>

                  <GlowCard>
                    <h3>Protocol Summary</h3>

                    <div className="protocol-list">
                      {protocolData.map((item) => (
                        <div className="protocol-row" key={item.name}>
                          <span>{item.name}</span>
                          <strong>{item.value}</strong>
                        </div>
                      ))}
                    </div>
                  </GlowCard>
                </div>

                {/* Recent packets */}
                <GlowCard>
                  <div className="section-heading">
                    <h3>Recent Packets</h3>

                    <button onClick={() => navigateTo("Packet Explorer")}>
                      View All
                    </button>
                  </div>

                  <div className="table-search">
                    <Search size={16} />

                    <input
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
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
                            <tr key={`${packet.timestamp}-${index}`}>
                              <td>{packet.timestamp}</td>
                              <td>{packet.source}</td>
                              <td>{packet.destination}</td>
                              <td>{packet.protocol}</td>
                              <td>{formatBytes(packet.size)}</td>
                            </tr>
                          ))}

                        {filteredPackets.length === 0 && (
                          <tr>
                            <td colSpan={5}>
                              No packets found.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </GlowCard>
              </>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;

