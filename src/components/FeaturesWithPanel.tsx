
import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import "./FeaturesWithPanel.css";

interface Feature {
  number: string;
  title: string;
  description: string;
  icon: string;
  details: string[];
}

const features: Feature[] = [
  {
    number: "01",
    title: "Live Packet Capture",
    description: "Capture packets directly from your network interface.",
    icon: "◉",
    details: [
      "Real-time network monitoring",
      "Interface selection",
      "Live packet statistics",
    ],
  },
  {
    number: "02",
    title: "Protocol Analysis",
    description: "Identify and analyze network protocols.",
    icon: "⌘",
    details: [
      "TCP and UDP identification",
      "ICMP packet recognition",
      "Protocol distribution",
    ],
  },
  {
    number: "03",
    title: "Packet Inspection",
    description: "Inspect packet metadata and connection details.",
    icon: "⌕",
    details: [
      "Source and destination IP",
      "MAC address information",
      "Port and packet size",
    ],
  },
  {
    number: "04",
    title: "Traffic Monitoring",
    description: "Understand network traffic patterns.",
    icon: "↗",
    details: [
      "Traffic statistics",
      "Packet count tracking",
      "Network activity visualization",
    ],
  },
  {
    number: "05",
    title: "Export & Reporting",
    description: "Export captured traffic for further analysis.",
    icon: "⇩",
    details: [
      "CSV packet export",
      "Structured packet records",
      "Offline traffic analysis",
    ],
  },
];

export default function FeaturesWithPanel() {
  const [active, setActive] = useState(0);

  const selectedFeature = features[active];

  return (
    <section className="psa-features">
      <div className="psa-features-header">
        <span className="psa-section-label">SYSTEM CAPABILITIES</span>

        <h2>
          Built for <span>Network Analysis.</span>
        </h2>

        <p>
          Everything you need to observe, inspect, and understand network traffic.
        </p>
      </div>

      <div className="psa-features-layout">
        <div className="psa-feature-list">
          {features.map((feature, index) => (
            <motion.button
              key={feature.number}
              className={`psa-feature-item ${
                active === index ? "active" : ""
              }`}
              onClick={() => setActive(index)}
              whileHover={{ x: 4 }}
              whileTap={{ scale: 0.99 }}
            >
              <span className="psa-feature-icon">{feature.icon}</span>

              <span className="psa-feature-info">
                <span className="psa-feature-number">{feature.number}</span>
                <span className="psa-feature-title">{feature.title}</span>
                <span className="psa-feature-description">
                  {feature.description}
                </span>
              </span>

              <span className="psa-feature-arrow">
                {active === index ? "↗" : "→"}
              </span>
            </motion.button>
          ))}
        </div>

        <div className="psa-feature-panel">
          <AnimatePresence mode="wait">
            <motion.div
              key={active}
              className="psa-feature-panel-content"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.25 }}
            >
              <div className="psa-panel-top">
                <span className="psa-live-indicator" />
                <span>PSA / MODULE_{selectedFeature.number}</span>
                <span className="psa-panel-status">READY</span>
              </div>

              <div className="psa-panel-visual">
                <div className="psa-panel-orbit">
                  <div className="psa-panel-orbit-inner">
                    <span>{selectedFeature.icon}</span>
                  </div>
                </div>

                <div className="psa-panel-grid" />
              </div>

              <div className="psa-panel-information">
                <span className="psa-section-label">
                  FEATURE {selectedFeature.number}
                </span>

                <h3>{selectedFeature.title}</h3>

                <p>{selectedFeature.description}</p>

                <ul>
                  {selectedFeature.details.map((detail) => (
                    <li key={detail}>
                      <span>✓</span>
                      {detail}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="psa-panel-footer">
                <span>NETWORK INTELLIGENCE</span>
                <span>PSA // 2026</span>
              </div>
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </section>
  );
}

