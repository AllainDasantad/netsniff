export interface PacketInfo {
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  source_port?: number | string | null;
  destination_port?: number | string | null;
  size: number;
  raw_data?: number[];
  payload?: number[];
  tcp_flags?: string;
}

