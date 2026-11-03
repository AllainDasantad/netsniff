
use pcap::Device;
use serde::Serialize;
use std::net::Ipv6Addr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use tauri::{AppHandle, Emitter, State};

#[derive(Debug, Serialize, Clone)]
struct PacketInfo {
    timestamp: String,
    source: String,
    destination: String,
    protocol: String,
    source_port: String,
    destination_port: String,
    size: usize,
    raw_data: Vec<u8>,
    payload: Vec<u8>,
    tcp_flags: String,
}

struct CaptureState {
    running: Mutex<Option<Arc<AtomicBool>>>,
}

fn clear_capture_state(state: &CaptureState, flag: &Arc<AtomicBool>) {
    if let Ok(mut running) = state.running.lock() {
        if running
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, flag))
        {
            *running = None;
        }
    }
}

#[tauri::command]
fn list_interfaces() -> Result<Vec<String>, String> {
    Device::list()
        .map_err(|e| e.to_string())
        .map(|devices| devices.into_iter().map(|d| d.name).collect())
}

#[tauri::command]
fn start_capture(
    app: AppHandle,
    interface_name: String,
    state: State<'_, Arc<CaptureState>>,
) -> Result<(), String> {
    let mut running = state.running.lock().map_err(|e| e.to_string())?;

    if running.is_some() {
        return Err("Capture is already running".into());
    }

    let device = Device::list()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| "Interface not found".to_string())?;

    let stop_flag = Arc::new(AtomicBool::new(false));
    *running = Some(stop_flag.clone());

    let capture_state = Arc::clone(state.inner());
    let thread_stop_flag = Arc::clone(&stop_flag);

    drop(running);

    thread::spawn(move || {
        let result = pcap::Capture::from_device(device)
            .map_err(|e| e.to_string())
            .and_then(|builder| {
                builder
                    .promisc(true)
                    .snaplen(65535)
                    .timeout(1000)
                    .open()
                    .map_err(|e| e.to_string())
            });

        let mut capture = match result {
            Ok(capture) => capture,
            Err(error) => {
                let _ = app.emit("capture-error", error);
                let _ = app.emit("capture-stopped", ());
                clear_capture_state(&capture_state, &thread_stop_flag);
                return;
            }
        };

        let _ = app.emit("capture-started", ());

        while !thread_stop_flag.load(Ordering::Relaxed) {
            match capture.next_packet() {
                Ok(packet) => {
                    let info = parse_packet(
                        packet.data,
                        packet.header.len as usize,
                    );

                    let _ = app.emit("packet-captured", info);
                }

                Err(pcap::Error::TimeoutExpired) => continue,

                Err(error) => {
                    let _ = app.emit("capture-error", error.to_string());
                    break;
                }
            }
        }

        let _ = app.emit("capture-stopped", ());
        clear_capture_state(&capture_state, &thread_stop_flag);
    });

    Ok(())
}

#[tauri::command]
fn stop_capture(
    state: State<'_, Arc<CaptureState>>,
) -> Result<(), String> {
    let mut running = state.running.lock().map_err(|e| e.to_string())?;

    if let Some(flag) = running.take() {
        flag.store(true, Ordering::Relaxed);
    }

    Ok(())
}

// Parse TCP flags into readable names.
fn parse_tcp_flags(flags: u8) -> String {
    let mut names = Vec::new();

    if flags & 0x01 != 0 {
        names.push("FIN");
    }
    if flags & 0x02 != 0 {
        names.push("SYN");
    }
    if flags & 0x04 != 0 {
        names.push("RST");
    }
    if flags & 0x08 != 0 {
        names.push("PSH");
    }
    if flags & 0x10 != 0 {
        names.push("ACK");
    }
    if flags & 0x20 != 0 {
        names.push("URG");
    }
    if flags & 0x40 != 0 {
        names.push("ECE");
    }
    if flags & 0x80 != 0 {
        names.push("CWR");
    }

    if names.is_empty() {
        "-".to_string()
    } else {
        names.join(" ")
    }
}

// Parse TCP or UDP ports.
fn parse_ports(
    data: &[u8],
    transport: usize,
    source_port: &mut String,
    destination_port: &mut String,
) {
    if data.len() >= transport + 4 {
        *source_port = u16::from_be_bytes([
            data[transport],
            data[transport + 1],
        ])
        .to_string();

        *destination_port = u16::from_be_bytes([
            data[transport + 2],
            data[transport + 3],
        ])
        .to_string();
    }
}

// Parse TCP header, flags and payload.
fn parse_tcp(
    data: &[u8],
    transport: usize,
    payload: &mut Vec<u8>,
    tcp_flags: &mut String,
    source_port: &mut String,
    destination_port: &mut String,
) {
    parse_ports(
        data,
        transport,
        source_port,
        destination_port,
    );

    if data.len() < transport + 20 {
        return;
    }

    let header_length =
        ((data[transport + 12] >> 4) as usize) * 4;

    if header_length < 20
        || data.len() < transport + header_length
    {
        return;
    }

    *tcp_flags = parse_tcp_flags(data[transport + 13]);

    let payload_start = transport + header_length;

    if payload_start < data.len() {
        payload.extend_from_slice(&data[payload_start..]);
    }
}

// Parse IPv4.
fn parse_ipv4(
    data: &[u8],
    source: &mut String,
    destination: &mut String,
    protocol: &mut String,
    source_port: &mut String,
    destination_port: &mut String,
    payload: &mut Vec<u8>,
    tcp_flags: &mut String,
) {
    let ip = 14;

    if data.len() < ip + 20 {
        return;
    }

    let ihl = ((data[ip] & 0x0f) as usize) * 4;

    if ihl < 20 || data.len() < ip + ihl {
        return;
    }

    *source = format!(
        "{}.{}.{}.{}",
        data[ip + 12],
        data[ip + 13],
        data[ip + 14],
        data[ip + 15]
    );

    *destination = format!(
        "{}.{}.{}.{}",
        data[ip + 16],
        data[ip + 17],
        data[ip + 18],
        data[ip + 19]
    );

    let total_length =
        u16::from_be_bytes([data[ip + 2], data[ip + 3]]) as usize;

    let packet_end = (ip + total_length).min(data.len());

    // IPv4 fragmented packets are not reassembled here.
    let fragment =
        u16::from_be_bytes([data[ip + 6], data[ip + 7]]);

    if fragment & 0x3fff != 0 {
        *protocol = "IPv4 Fragment".into();
        return;
    }

    let transport = ip + ihl;

    match data[ip + 9] {
        6 => {
            *protocol = "TCP".into();

            let bounded = &data[..packet_end];

            parse_tcp(
                bounded,
                transport,
                payload,
                tcp_flags,
                source_port,
                destination_port,
            );
        }

        17 => {
            *protocol = "UDP".into();

            parse_ports(
                data,
                transport,
                source_port,
                destination_port,
            );

            if data.len() >= transport + 8 {
                let udp_length =
                    u16::from_be_bytes([
                        data[transport + 4],
                        data[transport + 5],
                    ]) as usize;

                let start = transport + 8;
                let end = (transport + udp_length)
                    .min(packet_end)
                    .min(data.len());

                if start < end {
                    payload.extend_from_slice(&data[start..end]);
                }
            }
        }

        1 => *protocol = "ICMP".into(),
        _ => *protocol = "IPv4".into(),
    }
}

// Parse IPv6 including common extension headers.
fn parse_ipv6(
    data: &[u8],
    source: &mut String,
    destination: &mut String,
    protocol: &mut String,
    source_port: &mut String,
    destination_port: &mut String,
    payload: &mut Vec<u8>,
    tcp_flags: &mut String,
) {
    let ip = 14;

    if data.len() < ip + 40 {
        return;
    }

    let src: [u8; 16] = data[ip + 8..ip + 24]
        .try_into()
        .unwrap();

    let dst: [u8; 16] = data[ip + 24..ip + 40]
        .try_into()
        .unwrap();

    *source = Ipv6Addr::from(src).to_string();
    *destination = Ipv6Addr::from(dst).to_string();

    let payload_length =
        u16::from_be_bytes([data[ip + 4], data[ip + 5]]) as usize;

    let packet_end =
        (ip + 40 + payload_length).min(data.len());

    let mut next_header = data[ip + 6];
    let mut transport = ip + 40;

    // Walk common IPv6 extension headers.
    loop {
        match next_header {
            // Hop-by-Hop, Routing, Destination Options
            0 | 43 | 60 => {
                if transport + 2 > packet_end {
                    return;
                }

                let next = data[transport];
                let length =
                    (data[transport + 1] as usize + 1) * 8;

                if transport + length > packet_end {
                    return;
                }

                next_header = next;
                transport += length;
            }

            // Fragment header
            44 => {
                if transport + 8 > packet_end {
                    return;
                }

                let next = data[transport];

                let fragment =
                    u16::from_be_bytes([
                        data[transport + 2],
                        data[transport + 3],
                    ]);

                if fragment & 0xfff8 != 0 {
                    *protocol = "IPv6 Fragment".into();
                    return;
                }

                next_header = next;
                transport += 8;
            }

            // Authentication header
            51 => {
                if transport + 2 > packet_end {
                    return;
                }

                let next = data[transport];
                let length =
                    (data[transport + 1] as usize + 2) * 4;

                if transport + length > packet_end {
                    return;
                }

                next_header = next;
                transport += length;
            }

            _ => break,
        }
    }

    match next_header {
        6 => {
            *protocol = "TCP".into();

            parse_tcp(
                &data[..packet_end],
                transport,
                payload,
                tcp_flags,
                source_port,
                destination_port,
            );
        }

        17 => {
            *protocol = "UDP".into();

            parse_ports(
                data,
                transport,
                source_port,
                destination_port,
            );

            if transport + 8 <= packet_end {
                let udp_length =
                    u16::from_be_bytes([
                        data[transport + 4],
                        data[transport + 5],
                    ]) as usize;

                let start = transport + 8;
                let end = (transport + udp_length)
                    .min(packet_end);

                if start < end {
                    payload.extend_from_slice(&data[start..end]);
                }
            }
        }

        58 => *protocol = "ICMPv6".into(),
        _ => *protocol = "IPv6".into(),
    }
}

fn parse_packet(data: &[u8], size: usize) -> PacketInfo {
    let mut source = "Unknown".to_string();
    let mut destination = "Unknown".to_string();
    let mut protocol = "Other".to_string();
    let mut source_port = "-".to_string();
    let mut destination_port = "-".to_string();
    let mut payload = Vec::new();
    let mut tcp_flags = "-".to_string();

    if data.len() >= 14 {
        let ethertype =
            u16::from_be_bytes([data[12], data[13]]);

        match ethertype {
            0x0800 => parse_ipv4(
                data,
                &mut source,
                &mut destination,
                &mut protocol,
                &mut source_port,
                &mut destination_port,
                &mut payload,
                &mut tcp_flags,
            ),

            0x86dd => parse_ipv6(
                data,
                &mut source,
                &mut destination,
                &mut protocol,
                &mut source_port,
                &mut destination_port,
                &mut payload,
                &mut tcp_flags,
            ),

            _ => {}
        }
    }

    PacketInfo {
        timestamp: chrono::Utc::now().to_rfc3339(),
        source,
        destination,
        protocol,
        source_port,
        destination_port,
        size,
        raw_data: data.to_vec(),
        payload,
        tcp_flags,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Arc::new(CaptureState {
            running: Mutex::new(None),
        }))
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            list_interfaces,
            start_capture,
            stop_capture
        ])
        .run(tauri::generate_context!())
        .expect("error while running application");
}

