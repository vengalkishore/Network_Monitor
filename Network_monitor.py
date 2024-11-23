import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTableWidget, QTableWidgetItem, 
                             QVBoxLayout, QPushButton, QLineEdit, QFileDialog, QWidget, 
                             QHeaderView, QTextEdit, QMessageBox, QInputDialog, QHBoxLayout,
                             QGroupBox, QSplitter)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR

class SnifferThread(QThread):
    packet_captured = pyqtSignal(object, int)
    stop_sniffing = False  
    def run(self):
        sniff(prn=self.handle_packet, store=False, stop_filter=self.should_stop_sniffing)

    def handle_packet(self, packet):
        if not self.stop_sniffing:
            self.packet_captured.emit(packet, len(packet))

    def should_stop_sniffing(self, packet):
        return self.stop_sniffing

    def start_sniffing(self):
        self.stop_sniffing = False
        self.start()

    def stop_sniffing_now(self):
        self.stop_sniffing = True

class NetworkMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.packets = []
        self.sniffer_thread = SnifferThread()
        self.sniffer_thread.packet_captured.connect(self.process_packet)

    def initUI(self):
        self.setWindowTitle("Enhanced Network Monitor")
        self.setGeometry(100, 100, 1200, 800)
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        control_panel = QGroupBox("Controls")
        control_layout = QHBoxLayout(control_panel)
        main_layout.addWidget(control_panel)

        self.start_button = QPushButton("Start Capturing")
        self.start_button.clicked.connect(self.start_capturing)
        control_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Capturing")
        self.stop_button.clicked.connect(self.stop_capturing)
        control_layout.addWidget(self.stop_button)

        self.save_button = QPushButton("Save Logs")
        self.save_button.clicked.connect(self.save_logs)
        control_layout.addWidget(self.save_button)

        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Search...")
        control_layout.addWidget(self.search_field)

        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_logs)
        control_layout.addWidget(self.search_button)
        splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(splitter)
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["No.", "Source IP:Port", "Destination IP:Port", "Protocol", "Domain URL", "Packet Length"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self.show_packet_details)
        splitter.addWidget(self.table)
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        splitter.addWidget(self.packet_details)
        
        self.statusBar().showMessage("Ready")
        self.show()

    def start_capturing(self):
        self.sniffer_thread.start_sniffing()
        self.statusBar().showMessage("Capturing started")

    def stop_capturing(self):
        self.sniffer_thread.stop_sniffing_now()
        self.statusBar().showMessage("Capturing stopped")

    def process_packet(self, packet, index):
        if IP in packet:
            self.packets.append(packet)

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            protocol_name = "TCP" if protocol == 6 else "UDP" if protocol == 17 else "Other"
            src_port = packet.sport if TCP in packet or UDP in packet else "N/A"
            dst_port = packet.dport if TCP in packet or UDP in packet else "N/A"
            domain_url = packet[DNS].qd.qname.decode() if DNS in packet and packet[DNS].qd else "N/A"
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)
            self.table.setItem(row_position, 0, QTableWidgetItem(str(index)))
            self.table.setItem(row_position, 1, QTableWidgetItem(f"{src_ip}:{src_port}"))
            self.table.setItem(row_position, 2, QTableWidgetItem(f"{dst_ip}:{dst_port}"))
            self.table.setItem(row_position, 3, QTableWidgetItem(protocol_name))
            self.table.setItem(row_position, 4, QTableWidgetItem(domain_url))
            self.table.setItem(row_position, 5, QTableWidgetItem(str(len(packet))))

    def show_packet_details(self):
        selected_row = self.table.currentRow()
        if selected_row != -1:
            packet = self.packets[selected_row]
            self.packet_details.setText(packet.show(dump=True))

    def save_logs(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Logs", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            with open(file_name, 'w') as file:
                for i in range(self.table.rowCount()):
                    row_data = [
                        self.table.item(i, j).text() if self.table.item(i, j) else ""
                        for j in range(self.table.columnCount())
                    ]
                    file.write(" | ".join(row_data) + "\n")
                file.write("\nDetailed Packet Information:\n")
                for packet in self.packets:
                    file.write(packet.show(dump=True) + "\n")

    def search_logs(self):
        search_term = self.search_field.text()
        self.table.setRowCount(0)
        for i, packet in enumerate(self.packets):
            if search_term in packet.show(dump=True):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                protocol_name = "TCP" if protocol == 6 else "UDP" if protocol == 17 else "Other"
                src_port = packet.sport if TCP in packet or UDP in packet else "N/A"
                dst_port = packet.dport if TCP in packet or UDP in packet else "N/A"
                domain_url = packet[DNS].qd.qname.decode() if DNS in packet and packet[DNS].qd else "N/A"
                self.table.insertRow(self.table.rowCount())
                self.table.setItem(self.table.rowCount() - 1, 0, QTableWidgetItem(str(i + 1)))
                self.table.setItem(self.table.rowCount() - 1, 1, QTableWidgetItem(f"{src_ip}:{src_port}"))
                self.table.setItem(self.table.rowCount() - 1, 2, QTableWidgetItem(f"{dst_ip}:{dst_port}"))
                self.table.setItem(self.table.rowCount() - 1, 3, QTableWidgetItem(protocol_name))
                self.table.setItem(self.table.rowCount() - 1, 4, QTableWidgetItem(domain_url))
                self.table.setItem(self.table.rowCount() - 1, 5, QTableWidgetItem(str(len(packet))))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    monitor = NetworkMonitor()
    sys.exit(app.exec_())
