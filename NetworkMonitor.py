import sys
import time
import os
import numpy as np
import pandas as pd
from collections import deque
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QMutex, QMutexLocker
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QAction, QTableWidget, QTableWidgetItem, 
    QVBoxLayout, QLineEdit, QDialog, QFileDialog, 
    QStatusBar, QPushButton, QHBoxLayout, QTextEdit, QWidget, QLabel,
    QComboBox, QInputDialog, QMessageBox
)
from PyQt5.QtGui import QIcon
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, DNSQR, Dot11Deauth, DNS
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

class NetworkMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Network Traffic Anomaly Detection")
        self.setGeometry(100, 100, 1200, 800)
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["No.", "Source IP", "Destination IP", "Protocol", "Service", "Domain URL", "Timestamp"])
        self.table.horizontalHeader().setStretchLastSection(True)
        
        self.pending_alerts = deque(maxlen=1000)  
        self.monitored_protocols = set()
        self.monitored_services = set()
        self.custom_mode_addresses = set()
        self.custom_mode_enabled = False
        self.packets = deque(maxlen=10000)  
        self.model = IsolationForest(n_estimators=100, contamination=0.1)

        self.setup_ui()
        self.sniffer_thread = SnifferThread()
        self.sniffer_thread.packet_captured.connect(self.process_packet)
        self.sniffer_thread.start()

    def setup_ui(self):
        layout = QVBoxLayout()
        
        button_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh Capture")
        self.refresh_button.clicked.connect(self.refresh_capture)
        self.save_button = QPushButton("Save Logs")
        self.save_button.clicked.connect(self.save_logs)
        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Search...")
        self.search_field.textChanged.connect(self.search_logs)
        self.filter_button = QPushButton("Filter Logs")
        self.filter_button.clicked.connect(self.filter_logs)
        self.add_protocol_button = QPushButton("Add Protocol")
        self.add_protocol_button.clicked.connect(self.add_protocol)
        self.add_service_button = QPushButton("Add Service")
        self.add_service_button.clicked.connect(self.add_service)
        self.custom_address_field = QLineEdit()
        self.custom_address_field.setPlaceholderText("Enter custom addresses (comma-separated)")
        self.add_address_button = QPushButton("Add Addresses")
        self.add_address_button.clicked.connect(self.add_custom_addresses)
        self.pending_alerts_button = QPushButton("Pending Alerts")
        self.pending_alerts_button.clicked.connect(self.show_pending_alerts)
        self.toggle_custom_mode_button = QPushButton("Enable Custom Mode")
        self.toggle_custom_mode_button.setCheckable(True)
        self.toggle_custom_mode_button.clicked.connect(self.toggle_custom_mode)

        button_layout.addWidget(self.refresh_button)
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.search_field)
        button_layout.addWidget(self.filter_button)
        button_layout.addWidget(self.add_protocol_button)
        button_layout.addWidget(self.add_service_button)
        button_layout.addWidget(self.custom_address_field)
        button_layout.addWidget(self.add_address_button)
        button_layout.addWidget(self.pending_alerts_button)
        button_layout.addWidget(self.toggle_custom_mode_button)

        rule_layout = QHBoxLayout()
        self.rule_combobox = QComboBox()
        self.rule_combobox.addItems(["Rule 1: Block HTTP", "Rule 2: Alert on FTP", "Rule 3: Monitor DNS", "Rule 4: Monitor ARP", "Rule 5: Monitor ICMP"])
        self.apply_rule_button = QPushButton("Apply Rule")
        self.apply_rule_button.clicked.connect(self.apply_rule)
        
        rule_layout.addWidget(QLabel("Select Rule:"))
        rule_layout.addWidget(self.rule_combobox)
        rule_layout.addWidget(self.apply_rule_button)

        layout.addLayout(button_layout)
        layout.addLayout(rule_layout)
        layout.addWidget(self.table)
        
        self.packet_figure = Figure()
        self.packet_canvas = FigureCanvas(self.packet_figure)
        layout.addWidget(self.packet_canvas)

        self.central_widget.setLayout(layout)
        self.status_bar.showMessage("Ready")

        # Fit model with initial data to avoid NotFittedError
        self.initial_model_fitting()

    def toggle_custom_mode(self):
        self.custom_mode_enabled = self.toggle_custom_mode_button.isChecked()
        self.toggle_custom_mode_button.setText("Disable Custom Mode" if self.custom_mode_enabled else "Enable Custom Mode")
        self.status_bar.showMessage("Custom Mode Enabled" if self.custom_mode_enabled else "Custom Mode Disabled")

    def initial_model_fitting(self):
        """Initial fitting of the IsolationForest model to avoid NotFittedError."""
        try:
            dummy_data = np.random.rand(10, 3)  
            self.model.fit(dummy_data)  
        except Exception as e:
            self.status_bar.showMessage(f"Initial model fitting error: {str(e)}")

    def process_packet(self, packet, index):
        timestamp = time.time()
        src_ip = packet[IP].src if IP in packet else "N/A"
        dst_ip = packet[IP].dst if IP in packet else "N/A"
        protocol_name = self.get_protocol_name(packet)
        service_name = self.get_service_name(packet)
        domain_url = self.get_domain_url(packet)

        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(index)))
        self.table.setItem(row, 1, QTableWidgetItem(src_ip))
        self.table.setItem(row, 2, QTableWidgetItem(dst_ip))
        self.table.setItem(row, 3, QTableWidgetItem(protocol_name))
        self.table.setItem(row, 4, QTableWidgetItem(service_name))
        self.table.setItem(row, 5, QTableWidgetItem(domain_url if domain_url else "N/A"))
        self.table.setItem(row, 6, QTableWidgetItem(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))))

        self.table.scrollToBottom()

        try:
            self.check_monitored_protocols(packet, src_ip, dst_ip, protocol_name)
            self.check_monitored_services(packet, src_ip, dst_ip)
            self.check_custom_mode(packet, src_ip, dst_ip)
            self.detect_deauthentication_attack(packet, src_ip, dst_ip)
        except Exception as e:
            self.status_bar.showMessage(f"Error processing packet: {str(e)}")
            print(f"Error processing packet: {str(e)}")  

        self.packets.append([src_ip, dst_ip, protocol_name, service_name, domain_url, timestamp])
        self.analyze_packets()

    def get_protocol_name(self, packet):
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(Dot11Deauth):
            return "Deauth"
        else:
            return "Unknown"

    def get_service_name(self, packet):
        port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else None
        services = {
            80: 'HTTP',
            443: 'HTTPS',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS'
            # Add other common services and ports here
        }
        return services.get(port, "Unknown")

    def get_domain_url(self, packet):
        try:
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                if hasattr(dns_layer, 'qd') and dns_layer.qd is not None:
                    return dns_layer.qd.qname.decode()
        except Exception as e:
            self.status_bar.showMessage(f"Error extracting domain URL: {str(e)}")
            return None

    def analyze_packets(self):
        if len(self.packets) < 2:
            return  

        try:
            X = np.array([[packet[0], packet[1], packet[2]] for packet in self.packets])
            self.model.fit(X)
            y_pred = self.model.predict(X)
            
            anomaly_scores = self.model.decision_function(X)
            anomalies = np.where(y_pred == -1)[0]
            
            self.plot_anomalies(anomaly_scores, anomalies)
        except NotFittedError as e:
            self.status_bar.showMessage("Model not fitted. Please capture more data.")
        except Exception as e:
            self.status_bar.showMessage(f"Error analyzing packets: {str(e)}")
            print(f"Error analyzing packets: {str(e)}")  

    def plot_anomalies(self, scores, anomalies):
        self.packet_figure.clear()
        ax = self.packet_figure.add_subplot(111)
        ax.plot(scores, label="Anomaly Score")
        ax.scatter(anomalies, scores[anomalies], color='red', label="Anomalies")
        ax.legend()
        self.packet_canvas.draw()

    def check_monitored_protocols(self, packet, src_ip, dst_ip, protocol_name):
        if protocol_name in self.monitored_protocols:
            alert_msg = f"Monitored Protocol Alert: {protocol_name} detected between {src_ip} and {dst_ip}"
            self.pending_alerts.append(alert_msg)
            self.status_bar.showMessage(alert_msg)

    def check_monitored_services(self, packet, src_ip, dst_ip):
        service_name = self.get_service_name(packet)
        if service_name in self.monitored_services:
            alert_msg = f"Monitored Service Alert: {service_name} detected between {src_ip} and {dst_ip}"
            self.pending_alerts.append(alert_msg)
            self.status_bar.showMessage(alert_msg)

    def check_custom_mode(self, packet, src_ip, dst_ip):
        if self.custom_mode_enabled and (src_ip in self.custom_mode_addresses or dst_ip in self.custom_mode_addresses):
            alert_msg = f"Custom Mode Alert: Traffic detected between {src_ip} and {dst_ip}"
            self.pending_alerts.append(alert_msg)
            self.status_bar.showMessage(alert_msg)

    def detect_deauthentication_attack(self, packet, src_ip, dst_ip):
        if packet.haslayer(Dot11Deauth):
            alert_msg = f"Deauthentication Attack Alert: Deauthentication frame detected from {src_ip} to {dst_ip}"
            self.pending_alerts.append(alert_msg)
            self.status_bar.showMessage(alert_msg)

    def refresh_capture(self):
        self.table.setRowCount(0)
        self.packets.clear()
        self.status_bar.showMessage("Capture refreshed")

    def save_logs(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Logs", "", "CSV Files (*.csv);;All Files (*)", options=options)
        if file_name:
            try:
                df = pd.DataFrame(list(self.packets), columns=["Source IP", "Destination IP", "Protocol", "Service", "Domain URL", "Timestamp"])
                df.to_csv(file_name, index=False)
                self.status_bar.showMessage("Logs saved successfully")
            except Exception as e:
                self.status_bar.showMessage(f"Error saving logs: {str(e)}")

    def search_logs(self, text):
        for row in range(self.table.rowCount()):
            item_found = any(text.lower() in str(self.table.item(row, col).text()).lower() for col in range(self.table.columnCount()))
            self.table.setRowHidden(row, not item_found)

    def filter_logs(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Filter Logs")
        dialog_layout = QVBoxLayout()
        
        filter_field = QLineEdit()
        filter_field.setPlaceholderText("Enter filter criteria (e.g., Source IP, Protocol, etc.)")
        dialog_layout.addWidget(filter_field)
        
        apply_button = QPushButton("Apply Filter")
        apply_button.clicked.connect(lambda: self.apply_filter(dialog, filter_field.text()))
        dialog_layout.addWidget(apply_button)
        
        dialog.setLayout(dialog_layout)
        dialog.exec_()

    def apply_filter(self, dialog, criteria):
        dialog.accept()
        for row in range(self.table.rowCount()):
            item_found = any(criteria.lower() in str(self.table.item(row, col).text()).lower() for col in range(self.table.columnCount()))
            self.table.setRowHidden(row, not item_found)

    def add_protocol(self):
        protocol, ok = QInputDialog.getText(self, "Add Protocol", "Enter the protocol name:")
        if ok and protocol:
            self.monitored_protocols.add(protocol)
            self.status_bar.showMessage(f"Protocol '{protocol}' added to monitored protocols")

    def add_service(self):
        service, ok = QInputDialog.getText(self, "Add Service", "Enter the service name:")
        if ok and service:
            self.monitored_services.add(service)
            self.status_bar.showMessage(f"Service '{service}' added to monitored services")

    def add_custom_addresses(self):
        addresses = self.custom_address_field.text().split(',')
        self.custom_mode_addresses.update(address.strip() for address in addresses)
        self.custom_address_field.clear()
        self.status_bar.showMessage("Custom addresses added")

    def show_pending_alerts(self):
        alerts_dialog = QDialog(self)
        alerts_dialog.setWindowTitle("Pending Alerts")
        alerts_layout = QVBoxLayout()
        
        alerts_text_edit = QTextEdit()
        alerts_text_edit.setReadOnly(True)
        alerts_text_edit.setText("\n".join(self.pending_alerts))
        alerts_layout.addWidget(alerts_text_edit)
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(alerts_dialog.close)
        alerts_layout.addWidget(close_button)
        
        alerts_dialog.setLayout(alerts_layout)
        alerts_dialog.exec_()

    def apply_rule(self):
        selected_rule = self.rule_combobox.currentText()
        if "Block HTTP" in selected_rule:
            self.monitored_services.add("HTTP")
        elif "Alert on FTP" in selected_rule:
            self.monitored_services.add("FTP")
        elif "Monitor DNS" in selected_rule:
            self.monitored_services.add("DNS")
        elif "Monitor ARP" in selected_rule:
            self.monitored_protocols.add("ARP")
        elif "Monitor ICMP" in selected_rule:
            self.monitored_protocols.add("ICMP")
        self.status_bar.showMessage(f"Applied rule: {selected_rule}")

class SnifferThread(QThread):
    packet_captured = pyqtSignal(object, int)

    def __init__(self):
        super().__init__()
        self.mutex = QMutex()
        self.index = 0

    def run(self):
        sniff(prn=self.handle_packet, store=False)

    def handle_packet(self, packet):
        with QMutexLocker(self.mutex):
            self.packet_captured.emit(packet, self.index)
            self.index += 1

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkMonitor()
    window.show()
    sys.exit(app.exec_())

