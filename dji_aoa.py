#!/usr/bin/env python3

import os, sys, struct, threading, socket, time, signal, errno, queue

if os.geteuid() != 0:
    sys.exit("Run as root (sudo)")

PC_IP   = sys.argv[1] if len(sys.argv) > 1 else None
PC_PORT = 5600

GADGET  = "/sys/kernel/config/usb_gadget/dji"
FFS_MNT = "/dev/ffs-dji"

# ── USB constants ─────────────────────────────────────────────────────────────
USB_DT_INTERFACE       = 4
USB_DT_ENDPOINT        = 5
USB_ENDPOINT_XFER_BULK = 2

# AOA bRequest codes (host→device control transfers)
AOA_GET_PROTOCOL    = 51
AOA_SEND_STRING     = 52
AOA_START_ACCESSORY = 53

# FunctionFS magic numbers
FFS_DESCS_MAGIC = 1
FFS_STRS_MAGIC  = 2

# FunctionFS event types
FFS_BIND = 0; FFS_UNBIND = 1; FFS_ENABLE = 2; FFS_DISABLE = 3; FFS_SETUP = 4

# DUML framing
PORT_DUML = 0x7530
NODE_APP  = 0x02

# ── Gadget helpers ────────────────────────────────────────────────────────────

def _w(path, val):
    with open(path, 'w') as f: f.write(str(val))

def gadget_destroy():
    _w(f"{GADGET}/UDC", "") if os.path.exists(f"{GADGET}/UDC") else None
    os.system(f"umount {FFS_MNT} 2>/dev/null")
    os.system(f"[ -L '{GADGET}/configs/c.1/ffs.dji' ] && rm '{GADGET}/configs/c.1/ffs.dji'")
    os.system(f"rmdir {GADGET}/configs/c.1/strings/0x409 {GADGET}/configs/c.1 "
              f"{GADGET}/functions/ffs.dji {GADGET}/strings/0x409 {GADGET} 2>/dev/null")

def gadget_create(vid, pid):
    g = GADGET
    for d in [f"{g}/strings/0x409", f"{g}/configs/c.1/strings/0x409",
              f"{g}/functions/ffs.dji", FFS_MNT]:
        os.makedirs(d, exist_ok=True)
    _w(f"{g}/idVendor",  f"0x{vid:04x}"); _w(f"{g}/idProduct", f"0x{pid:04x}")
    _w(f"{g}/bcdUSB", "0x0200");           _w(f"{g}/bcdDevice", "0x0100")
    _w(f"{g}/strings/0x409/manufacturer", "Google Inc.")
    _w(f"{g}/strings/0x409/product",      "Android")
    _w(f"{g}/strings/0x409/serialnumber", "0123456789ABCDEF")
    _w(f"{g}/configs/c.1/bmAttributes", "0x80")
    _w(f"{g}/configs/c.1/MaxPower", "500")
    _w(f"{g}/configs/c.1/strings/0x409/configuration", "DJI")
    link = f"{g}/configs/c.1/ffs.dji"
    if not os.path.exists(link):
        os.symlink(f"{g}/functions/ffs.dji", link)
    if not os.path.ismount(FFS_MNT):
        os.system(f"mount -t functionfs dji {FFS_MNT}")

def gadget_bind():
    udcs = os.listdir("/sys/class/udc/")
    if not udcs: raise RuntimeError("No UDC found")
    udc = udcs[0]
    _w(f"{GADGET}/UDC", udc)
    print(f"[gadget] bound → {udc}")

def gadget_switch(vid, pid):
    _w(f"{GADGET}/UDC", ""); time.sleep(0.15)
    _w(f"{GADGET}/idVendor", f"0x{vid:04x}")
    _w(f"{GADGET}/idProduct", f"0x{pid:04x}")
    time.sleep(0.1); gadget_bind()
    print(f"[gadget] re-enumerated as {vid:#06x}:{pid:#06x}")

# ── FunctionFS descriptors ────────────────────────────────────────────────────

def ffs_descriptors():
    def intf(): return struct.pack('<BBBBBBBBB', 9, USB_DT_INTERFACE, 0,0,2, 0xff,0xff,0, 0)
    def ep(addr, maxpkt): return struct.pack('<BBBBHB', 7, USB_DT_ENDPOINT, addr, USB_ENDPOINT_XFER_BULK, maxpkt, 0)
    fs = intf() + ep(0x01, 64)  + ep(0x81, 64)
    hs = intf() + ep(0x01, 512) + ep(0x81, 512)
    hdr = struct.pack('<IIII', FFS_DESCS_MAGIC, 16+len(fs)+len(hs), 3, 3)
    return hdr + fs + hs

def ffs_strings():
    return struct.pack('<IIII', FFS_STRS_MAGIC, 16, 0, 0)

# ── DUML helpers ──────────────────────────────────────────────────────────────

def crc8(data):
    crc = 0x77
    for b in data:
        for _ in range(8):
            mix = (crc ^ b) & 1; crc >>= 1
            if mix: crc ^= 0x8C
            b >>= 1
    return crc & 0xFF

def crc16(data):
    crc = 0x3692
    for b in data:
        for _ in range(8):
            mix = (crc ^ b) & 1; crc >>= 1
            if mix: crc ^= 0x8408
            b >>= 1
    return crc & 0xFFFF

def duml_build(src, dst, seq, cmd_type, cmd_set, cmd_id, payload=b''):
    il = 13 + len(payload)
    inner = bytearray(il)
    inner[0] = 0x55
    lv = (1 << 10) | il
    inner[1] = lv & 0xFF; inner[2] = (lv >> 8) & 0xFF
    inner[3] = crc8(bytes(inner[:3]))
    inner[4] = src; inner[5] = dst
    inner[6] = seq & 0xFF; inner[7] = (seq >> 8) & 0xFF
    inner[8] = cmd_type; inner[9] = cmd_set; inner[10] = cmd_id
    inner[11:11+len(payload)] = payload
    c = crc16(bytes(inner[:il-2]))
    inner[il-2] = c & 0xFF; inner[il-1] = (c >> 8) & 0xFF
    outer = bytearray(8 + il)
    outer[0]=0x55; outer[1]=0xCC
    outer[2]=PORT_DUML&0xFF; outer[3]=(PORT_DUML>>8)&0xFF
    outer[4]=il&0xFF; outer[5]=(il>>8)&0xFF
    outer[8:] = inner
    return bytes(outer)

# ── Main session class ────────────────────────────────────────────────────────

DUMP_FILE   = "/tmp/dji_video_dump.h264"
DUMP_LIMIT  = 2 * 1024 * 1024   # 2 MB then close

class DjiAoa:
    def __init__(self):
        self.running  = False
        self.aoa_mode = False
        self.enabled  = threading.Event()
        self.video_start_sent = False
        self.seq = 1
        self.ep0 = self.ep_out = self.ep_in = None
        # TCP server for video
        self.tcp_srv  = None
        self._vid_q   = queue.Queue(maxsize=16)   # ~64KB max queue (~85ms at 6Mbps)
        self._rx_alive = False
        # File dump for first 2 MB
        self._dump_file = open(DUMP_FILE, 'wb')
        self._dump_bytes = 0
        print(f"[dump] Writing first {DUMP_LIMIT//1024}KB to {DUMP_FILE}")

    # ── Video output ──────────────────────────────────────────────────────────

    def _update_sps_pps(self, data):
        """Scan data for H.264 SPS (type 7) / PPS (type 8) NAL units and cache them."""
        i = 0
        while i < len(data) - 4:
            if data[i:i+4] == b'\x00\x00\x00\x01':
                if i + 4 < len(data):
                    nal_type = data[i+4] & 0x1F
                    if nal_type in (7, 8):   # SPS or PPS
                        # Find next start code to delimit this NAL
                        j = i + 4
                        while j < len(data) - 3:
                            if data[j:j+4] == b'\x00\x00\x00\x01':
                                break
                            j += 1
                        nal = data[i:j]
                        with self._sps_pps_lock:
                            if nal not in self._sps_pps:
                                self._sps_pps += nal
                                print(f"[video] cached NAL type {nal_type} ({len(nal)}B)")
            i += 1

    def start_tcp_server(self):
        self.tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_srv.bind(('0.0.0.0', PC_PORT))
        self.tcp_srv.listen(1)
        print(f"[video] TCP server listening on :{PC_PORT}")
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            try:
                self.tcp_srv.settimeout(1.0)
                conn, addr = self.tcp_srv.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                print(f"[video] PC connected from {addr}")
                threading.Thread(target=self._sender, args=(conn,), daemon=True).start()
            except socket.timeout:
                pass
            except Exception as e:
                if self.running: print(f"[video] accept error: {e}")

    def _sender(self, conn):
        """Drain the video queue to a single TCP client."""
        try:
            while self.running:
                try:
                    data = self._vid_q.get(timeout=1.0)
                except queue.Empty:
                    continue
                conn.sendall(data)
        except Exception as e:
            print(f"[video] client disconnected: {e}")
        finally:
            try: conn.close()
            except: pass

    def send_video(self, data):
        # Throttled stats
        self._video_bytes = getattr(self, '_video_bytes', 0) + len(data)
        now = time.time()
        _lr = getattr(self, '_video_last_report', 0)
        if now - _lr >= 5.0:
            kb = self._video_bytes // 1024
            print(f"[video] {kb} KB received so far")
            self._video_last_report = now
        # Dump to file
        if self._dump_file and self._dump_bytes < DUMP_LIMIT:
            remaining = DUMP_LIMIT - self._dump_bytes
            self._dump_file.write(data[:remaining])
            self._dump_bytes += min(len(data), remaining)
            if self._dump_bytes >= DUMP_LIMIT:
                self._dump_file.flush()
                self._dump_file.close()
                self._dump_file = None
                print(f"[dump] DONE — {DUMP_FILE} ready for ffprobe")
        # Non-blocking enqueue — drop OLDEST chunk if full to keep latency low
        try:
            self._vid_q.put_nowait(bytes(data))
        except queue.Full:
            try: self._vid_q.get_nowait()
            except queue.Empty: pass
            try: self._vid_q.put_nowait(bytes(data))
            except queue.Full: pass

    # ── DUML TX ───────────────────────────────────────────────────────────────

    def send_duml(self, dst, cmd_type, cmd_set, cmd_id, payload=b''):
        frame = duml_build(NODE_APP, dst, self.seq, cmd_type, cmd_set, cmd_id, payload)
        self.seq += 1
        try:
            self.ep_in.write(frame)
        except Exception as e:
            print(f"[TX] error: {e}")

    # Magic keep-alive payloads (from samuelsadok/dji_protocol video_out_mobile.py)
    # cmdId=0x99 "camcap_common" → dst 0x28  (subscribe to camera capture)
    MAGIC_PAYLOAD_99 = bytes([
        0x02, 0x02, 0x00, 0x00, 0xD5, 0x07, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x13, 0x00, 0x0D, 0x00,
        0x63, 0x61, 0x6D, 0x63, 0x61, 0x70, 0x5F,  # "camcap_
        0x63, 0x6F, 0x6D, 0x6D, 0x6F, 0x6E,         # common"
        0x00, 0x00, 0x00, 0x00,
    ])
    # cmdId=0x88 "APP" → dst 0x3C  (register as app client)
    MAGIC_PAYLOAD_88 = bytes([
        0x17, 0x00, 0x00, 0x23, 0x00,
        0x41, 0x50, 0x50,                            # "APP"
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ])

    def send_magic_packets(self):
        self.send_duml(0x28, 0x40, 0x00, 0x99, self.MAGIC_PAYLOAD_99)
        self.send_duml(0x3C, 0x40, 0x00, 0x88, self.MAGIC_PAYLOAD_88)

    def _magic_keepalive(self):
        """Keep video flowing: send magic packets every 5 s."""
        while self.running:
            time.sleep(5.0)
            if self.running:
                print("[magic] keepalive →")
                self.send_magic_packets()

    def send_video_start(self, src):
        time.sleep(0.1)
        print("[session] video start sequence →")

        # 1. Register as APP client with nodes 0x28 / 0x3C
        #    (from samuelsadok/dji_protocol — required to start video pipeline)
        self.send_magic_packets()
        time.sleep(0.2)

        # 2. Enable video link on 0x0E
        self.send_duml(0x0E, 0x40, 0x09, 0x09, bytes([0x01]))
        time.sleep(0.2)

        # 3. cs=09 id=1A to 0x0E
        self.send_duml(0x0E, 0x40, 0x09, 0x1A, bytes([0x01]))
        time.sleep(0.1)

        # 4. SET liveview (cs=07 id=1E) to video encoder 0x59
        lv_payload = bytes([0x01,0,0,0, 0x37,0,0,0] + [0]*40)
        self.send_duml(0x59, 0x40, 0x07, 0x1E, lv_payload)
        time.sleep(0.2)

        # 5. cs=09 id=06 to main session + video link
        self.send_duml(0x09, 0x40, 0x09, 0x06, bytes([0x01]))
        time.sleep(0.1)
        self.send_duml(0x0E, 0x40, 0x09, 0x06, bytes([0x01]))
        time.sleep(0.1)

        # Repeat magic packets immediately and then every 5 s
        self.send_magic_packets()
        threading.Thread(target=self._magic_keepalive, daemon=True).start()

    # ── Control endpoint (AOA handshake) ──────────────────────────────────────

    def ep0_loop(self):
        EV_SZ = 12
        STRING_NAMES = ['manufacturer','model','description','version','uri','serial']
        while self.running:
            try:
                ev = self.ep0.read(EV_SZ)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EINTR): continue
                if self.running: print(f"[ep0] read error: {e}")
                break
            if len(ev) < EV_SZ: continue
            setup = ev[:8]; ev_type = ev[8]

            if ev_type == FFS_SETUP:
                bRT, bReq, wVal, wIdx, wLen = struct.unpack('<BBHHH', setup)
                print(f"[ep0] SETUP bRT={bRT:#04x} bReq={bReq} wIdx={wIdx} wLen={wLen}")

                if bReq == AOA_GET_PROTOCOL:
                    self.ep0.write(struct.pack('<H', 2))

                elif bReq == AOA_SEND_STRING:
                    if wLen > 0:
                        s = self.ep0.read(wLen)
                        name = STRING_NAMES[wIdx] if wIdx < len(STRING_NAMES) else f"[{wIdx}]"
                        print(f"[ep0]   {name}: {s.decode('utf-8','replace').rstrip(chr(0))}")
                    self.ep0.write(b'')   # ACK

                elif bReq == AOA_START_ACCESSORY:
                    self.ep0.write(b'')   # ACK
                    threading.Thread(target=lambda: (time.sleep(0.1),
                        gadget_switch(0x18d1, 0x2d00),
                        setattr(self, 'aoa_mode', True)),
                        daemon=True).start()

                else:
                    # Stall unknown requests
                    pass

            elif ev_type == FFS_ENABLE:
                print("[ep0] ENABLE — interface active")
                self.enabled.set()
                # On re-ENABLE after DISABLE, restart rx_loop
                if not self._rx_alive:
                    threading.Thread(target=self.rx_loop, daemon=True).start()
            elif ev_type == FFS_DISABLE:
                print("[ep0] DISABLE — goggles disconnected, waiting for reconnect")
                self.video_start_sent = False
                self.enabled.clear()
            elif ev_type == FFS_BIND:
                print("[ep0] BIND")
            elif ev_type == FFS_UNBIND:
                print("[ep0] UNBIND")

    # ── Bulk RX (frames from goggles) ─────────────────────────────────────────

    def _probe_if_silent(self):
        """If goggles don't initiate after 1s, try sending cs=09 id=08 to them."""
        time.sleep(1.0)
        if not self.video_start_sent:
            print("[probe] No data from goggles — sending session probe")
            self.send_duml(0x09, 0x40, 0x09, 0x08, b'\x00')
            time.sleep(0.5)
            self.send_duml(0xFF, 0x40, 0x09, 0x08, b'\x00')  # broadcast

    def rx_loop(self):
        self._rx_alive = True
        print("[rx] waiting for ENABLE...")
        self.enabled.wait()
        print("[rx] starting — reading DUML from goggles")
        # Give goggles 1s to initiate; if nothing, send a probe
        threading.Thread(target=self._probe_if_silent, daemon=True).start()
        buf = bytearray()
        while self.running:
            try:
                chunk = self.ep_out.read(65536)
                if not chunk: continue
                buf.extend(chunk)
                buf = self._consume(buf)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EINTR): continue
                if self.running: print(f"[rx] error: {e}")
                break
        self._rx_alive = False
        print("[rx] loop exited — will restart on next ENABLE")

    def _consume(self, buf):
        pos = 0
        # Log any leading bytes that aren't 55 CC (might be raw H.264)
        start = pos
        while pos < len(buf) and (len(buf) - pos < 2 or buf[pos] != 0x55 or buf[pos+1] != 0xCC):
            pos += 1
        if pos > start:
            raw = buf[start:pos]
            print(f"[RX raw {len(raw)}B] {raw[:16].hex()}")
            if len(raw) > 4:
                self.send_video(raw)
            buf = buf[pos:]
            pos = 0
        while pos < len(buf):
            if len(buf) - pos < 8: break
            if buf[pos] != 0x55 or buf[pos+1] != 0xCC:
                pos += 1; continue
            port = buf[pos+2] | (buf[pos+3] << 8)
            il   = buf[pos+4] | (buf[pos+5] << 8)
            if il <= 0 or il > 65535: pos += 1; continue
            if len(buf) - pos < 8 + il: break
            inner = buf[pos+8:pos+8+il]
            self._dispatch(port, inner)
            pos += 8 + il
        return bytearray(buf[pos:])

    def _dispatch(self, port, inner):
        # Non-DUML port — likely video or other stream
        if port != PORT_DUML:
            self.send_video(inner)
            return

        if len(inner) < 11 or inner[0] != 0x55:
            # Not DUML — might be raw video on port 0x7530
            print(f"[RX raw {len(inner)}B] {inner[:8].hex()}")
            if len(inner) > 4:
                self.send_video(inner)
            return

        src      = inner[4]; cmd_type = inner[8]
        cmd_set  = inner[9]; cmd_id   = inner[10]
        payload  = inner[11:len(inner)-2] if len(inner) > 13 else b''

        # H.264 Annex-B in payload?
        if len(payload) > 4 and payload[:4] == b'\x00\x00\x00\x01':
            self.send_video(payload); return

        # ACK if requested
        if cmd_type & 0x40:
            self.send_duml(src, 0x20, cmd_set, cmd_id, b'\x00')

        # Liveview status from video encoder — log first DWORD (0=off, non-zero=on)
        if cmd_set == 0x06 and cmd_id == 0x1E and len(payload) >= 4:
            state = int.from_bytes(payload[:4], 'little')
            print(f"[LIVEVIEW] state={state:#010x} ({'ON' if state else 'OFF'})")

        if cmd_set == 0x09 and cmd_id == 0x08:
            if not (cmd_type & 0x40):
                self.send_duml(src, 0x20, 0x09, 0x08, b'\x00')
            if not self.video_start_sent:
                self.video_start_sent = True
                threading.Thread(target=self.send_video_start, args=(src,), daemon=True).start()

    # ── Main ─────────────────────────────────────────────────────────────────

    def run(self):
        self.running = True
        self.start_tcp_server()

        # Write FunctionFS descriptors before binding UDC
        self.ep0 = open(f"{FFS_MNT}/ep0", "r+b", buffering=0)
        self.ep0.write(ffs_descriptors())
        self.ep0.write(ffs_strings())
        print("[ffs] descriptors written")

        gadget_bind()

        # Wait for ep files to appear
        for _ in range(20):
            eps = [f for f in os.listdir(FFS_MNT) if f.startswith('ep') and f != 'ep0']
            if len(eps) >= 2: break
            time.sleep(0.1)
        eps = sorted(f for f in os.listdir(FFS_MNT) if f.startswith('ep') and f != 'ep0')
        print(f"[ffs] endpoints: {eps}")

        self.ep_out = open(f"{FFS_MNT}/{eps[0]}", "rb", buffering=0)  # OUT ep
        self.ep_in  = open(f"{FFS_MNT}/{eps[1]}", "wb", buffering=0)  # IN  ep

        threading.Thread(target=self.ep0_loop, daemon=True).start()
        threading.Thread(target=self.rx_loop,  daemon=True).start()

        print("\n[ready] Connect DJI Goggles USB-C → Pi Zero micro-USB")
        print(f"[ready] On PC run: ffplay tcp://$(hostname -I | awk '{{print $1}}'):{PC_PORT} -vcodec h264\n")

        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping...")
            self.running = False

def main():
    global PC_PORT
    gadget_destroy()
    time.sleep(0.3)
    gadget_create(0x18d1, 0x2d00)  # AOA VID/PID directly — no handshake needed

    app = DjiAoa()
    signal.signal(signal.SIGTERM, lambda *_: setattr(app, 'running', False))
    try:
        app.run()
    finally:
        gadget_destroy()

if __name__ == '__main__':
    main()
