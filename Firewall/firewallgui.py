import sys
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLineEdit, QVBoxLayout, QLabel, QMessageBox, QHBoxLayout, QTextEdit, QListWidget, QListWidgetItem
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import scapy.all as scapy
import time
from collections import defaultdict

# Giriş Ekranı
class LoginScreen(QWidget):
    def __init__(self, main_app_class):
        super().__init__()

        self.main_app_class = main_app_class  # Ana uygulamayı al

        self.setWindowTitle('Giriş Yap')
        self.setGeometry(0, 0, 800, 600)  # Ekran boyutunu daha uygun hale getirdik
        self.setStyleSheet("background-color: #2C2C2C; color: #FFFFFF;")  # Koyu gri arka plan

        # Başlık ve Resim
        self.title_label = QLabel('Firewall', self)
        self.title_label.setStyleSheet("font-size: 30px; font-weight: bold; color: #4CAF50;")
        
        self.hacker_image = QLabel(self)
        pixmap = QPixmap("hacker.png")  # Hacker resmini yükleyin (örneğin hacker_image.png)
        self.hacker_image.setPixmap(pixmap.scaled(100, 100, Qt.KeepAspectRatio))  # Resmi boyutlandır

        # UI Elemanları
        self.username_label = QLabel('Kullanıcı Adı:', self)
        self.password_label = QLabel('Şifre:', self)

        self.username_input = QLineEdit(self)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton('Giriş Yap', self)
        self.login_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px; border-radius: 5px;")

        # Layout düzeni
        layout = QVBoxLayout()

        # Başlık ve hacker resmini yatay olarak yerleştir
        header_layout = QHBoxLayout()
        header_layout.addWidget(self.title_label)
        header_layout.addWidget(self.hacker_image)
        header_layout.setAlignment(Qt.AlignCenter)  # Ortalamak için

        layout.addLayout(header_layout)
        
        # Giriş alanlarını ve butonları ortalamak için
        input_layout = QVBoxLayout()
        input_layout.addWidget(self.username_label)
        input_layout.addWidget(self.username_input)
        input_layout.addWidget(self.password_label)
        input_layout.addWidget(self.password_input)
        input_layout.addWidget(self.login_button)

        # Butonun ve giriş alanlarının genişliğini sınırlayalım
        self.username_input.setFixedWidth(250)
        self.password_input.setFixedWidth(250)
        self.login_button.setFixedWidth(250)

        input_layout.setAlignment(Qt.AlignCenter)  # Ortalamak için
        layout.addLayout(input_layout)

        layout.setSpacing(15)  # Aralarındaki boşluğu arttır

        # Ortalamak için QSpacerItem kullanmak
        layout.addStretch(1)

        self.setLayout(layout)

        # Butona tıklama fonksiyonu
        self.login_button.clicked.connect(self.check_credentials)

        # Giriş ekranını ekranın ortasında aç
        self.center()

    def check_credentials(self):
        # Şifre doğrulaması (örneğin "admin" ve "1234")
        username = self.username_input.text()
        password = self.password_input.text()

        if username == "admin" and password == "1234":
            self.accept_login()
        else:
            self.show_error("Yanlış kullanıcı adı veya şifre.")

    def accept_login(self):
        self.main_app = self.main_app_class()  # Ana uygulamayı başlat
        self.main_app.show()  # Ana uygulamayı göster
        self.close()  # Giriş ekranını kapat

    def show_error(self, message):
        QMessageBox.critical(self, "Hata", message)

    def center(self):
        screen_geometry = QApplication.primaryScreen().geometry()  # Ekranın boyutlarını al
        window_geometry = self.geometry()  # Pencere boyutlarını al
        center_x = (screen_geometry.width() - window_geometry.width()) // 2  # Ekranın ortası
        center_y = (screen_geometry.height() - window_geometry.height()) // 2  # Ekranın ortası
        self.move(center_x, center_y)  # Pencereyi ortala


# Dinamik IP Engelleyici
class DynamicIPBlock:
    def __init__(self):
        self.ip_activity = defaultdict(int)
        self.blocked_ips = self.load_blocked_ips()  # Engellenen IP'leri dosyadan yükle
        self.threshold = 100
        self.time_window = 60
        self.last_checked = time.time()

    def load_blocked_ips(self):
        try:
            with open("blocked_ips.txt", "r") as file:
                return set(line.strip() for line in file.readlines())
        except FileNotFoundError:
            return set()

    def save_blocked_ips(self):
        with open("blocked_ips.txt", "w") as file:
            for ip in self.blocked_ips:
                file.write(ip + "\n")

    def check_and_block(self, src_ip):
        current_time = time.time()
        if current_time - self.last_checked > self.time_window:
            self.reset_activity()

        self.ip_activity[src_ip] += 1
        if self.ip_activity[src_ip] > self.threshold:
            self.block_ip(src_ip)

    def reset_activity(self):
        self.ip_activity.clear()
        self.last_checked = time.time()

    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.save_blocked_ips()  # Engellenen IP'yi kaydet
            return ip
        return None

    def unblock_ip(self, ip):
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.save_blocked_ips()  # Engellenen IP'yi kaydet
            return ip
        return None


# Packet Capture Thread
class PacketCaptureThread(QThread):
    new_packet_signal = pyqtSignal(str)
    blocked_ip_signal = pyqtSignal(str)

    def __init__(self, block_ips, dynamic_blocker):
        super().__init__()
        self.block_ips = block_ips
        self.is_running = True
        self.dynamic_blocker = dynamic_blocker

    def run(self):
        try:
            while self.is_running:
                packets = scapy.sniff(count=1)
                for packet in packets:
                    if packet.haslayer(scapy.IP):
                        src_ip = packet[scapy.IP].src
                        dst_ip = packet[scapy.IP].dst
                        src_port = packet.sport if hasattr(packet, 'sport') else "N/A"
                        dst_port = packet.dport if hasattr(packet, 'dport') else "N/A"
                        
                        # Dinamik IP engellemeyi kontrol et
                        blocked_ip = self.dynamic_blocker.check_and_block(src_ip)
                        if blocked_ip:
                            self.blocked_ip_signal.emit(blocked_ip)
                        
                        if src_ip in self.block_ips or dst_ip in self.block_ips:
                            continue
                        packet_info = f"Source IP: {src_ip}, Source Port: {src_port}, Dest IP: {dst_ip}, Dest Port: {dst_port}, Protocol: {packet.proto}"
                        self.new_packet_signal.emit(packet_info)
                    time.sleep(1)  # Trafiği yavaşlatmak için 1 saniye bekleme
        except Exception as e:
            self.new_packet_signal.emit(f"Hata: {str(e)}")

    def stop(self):
        self.is_running = False
        self.wait()


# Ana Uygulama Ekranı
class MainApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Ana Uygulama')
        self.setGeometry(0, 0, 1920, 1080)  # Tam ekran yapmak için
        self.setStyleSheet("background-color: #000000; color: #FFFFFF;")  # Siyah arka plan

        # UI Elemanları
        self.start_button = QPushButton('Başlat', self)
        self.stop_button = QPushButton('Durdur', self)
        self.block_button = QPushButton('IP Engelle', self)
        self.unblock_button = QPushButton('Engeli Kaldır', self)
        self.exit_button = QPushButton('Çıkış', self)
        self.log_area = QTextEdit(self)
        self.ip_input = QLineEdit(self)
        self.blocked_ip_list = QListWidget(self)

        self.start_button.setStyleSheet("background-color: #4CAF50; color: white;")
        self.stop_button.setStyleSheet("background-color: #F44336; color: white;")
        self.block_button.setStyleSheet("background-color: #FF9800; color: white;")
        self.unblock_button.setStyleSheet("background-color: #2196F3; color: white;")
        self.exit_button.setStyleSheet("background-color: #9E9E9E; color: white;")

        self.start_button.setFixedWidth(150)
        self.stop_button.setFixedWidth(150)
        self.block_button.setFixedWidth(150)
        self.unblock_button.setFixedWidth(150)
        self.exit_button.setFixedWidth(150)

        self.log_area.setReadOnly(True)
        self.ip_input.setPlaceholderText("Engellenecek IP adresini girin...")

        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        right_layout = QVBoxLayout()

        left_layout.addWidget(self.start_button)
        left_layout.addWidget(self.stop_button)
        left_layout.addWidget(self.ip_input)
        left_layout.addWidget(self.block_button)
        left_layout.addWidget(self.unblock_button)
        left_layout.addWidget(self.log_area)
        left_layout.addWidget(self.exit_button)

        right_layout.addWidget(self.blocked_ip_list)
        main_layout.addLayout(left_layout)
        main_layout.addLayout(right_layout)
        self.setLayout(main_layout)

        self.start_button.clicked.connect(self.start_firewall)
        self.stop_button.clicked.connect(self.stop_firewall)
        self.block_button.clicked.connect(self.block_ip)
        self.unblock_button.clicked.connect(self.unblock_ip)
        self.exit_button.clicked.connect(self.exit_app)

        self.capture_thread = None
        self.blocked_ips = []
        self.dynamic_blocker = DynamicIPBlock()  # Dinamik IP engelleyici başlatıldı

        self.load_blocked_ips()

    def load_blocked_ips(self):
        self.blocked_ips = list(self.dynamic_blocker.blocked_ips)
        self.update_blocked_ip_list()

    def start_firewall(self):
        try:
            self.capture_thread = PacketCaptureThread(self.blocked_ips, self.dynamic_blocker)
            self.capture_thread.new_packet_signal.connect(self.update_log)
            self.capture_thread.blocked_ip_signal.connect(self.update_blocked_ip_list)
            self.capture_thread.start()
            self.update_log("Firewall Başlatıldı.")
        except Exception as e:
            self.update_log(f"Hata: {str(e)}")

    def stop_firewall(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.update_log("Firewall Durduruldu.")

    def block_ip(self):
        ip = self.ip_input.text()
        if ip:
            blocked_ip = self.dynamic_blocker.block_ip(ip)
            if blocked_ip:
                self.blocked_ips.append(blocked_ip)
                self.update_blocked_ip_list()
                self.update_log(f"IP Engellendi: {blocked_ip}")

    def unblock_ip(self):
        selected_item = self.blocked_ip_list.currentItem()
        if selected_item:
            ip_to_unblock = selected_item.text()
            unblocked_ip = self.dynamic_blocker.unblock_ip(ip_to_unblock)
            if unblocked_ip:
                self.blocked_ips.remove(unblocked_ip)
                self.update_blocked_ip_list()
                self.update_log(f"IP Engel Kaldırıldı: {unblocked_ip}")

    def update_log(self, message):
        self.log_area.append(message)

    def update_blocked_ip_list(self, blocked_ip=None):
        self.blocked_ip_list.clear()
        self.blocked_ip_list.addItems(self.blocked_ips)

    def exit_app(self):
        self.close()


# Ana Çalıştırıcı
def main():
    app = QApplication(sys.argv)
    login_screen = LoginScreen(MainApp)
    login_screen.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
