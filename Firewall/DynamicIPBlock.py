import time
from collections import defaultdict

class DynamicIPBlock:
    def __init__(self):
        # IP aktivitelerini saklamak için bir defaultdict (her IP için gönderilen paket sayısı)
        self.ip_activity = defaultdict(int)
        
        # Engellenen IP'lerin saklandığı küme
        self.blocked_ips = set()
        
        # DDoS saldırısı için paket limiti (örneğin 100 paket)
        self.threshold = 100  
        
        # Aktiviteyi sıfırlamak için kullanılacak zaman penceresi (örneğin 60 saniye)
        self.time_window = 60
        
        # Son kontrol zamanını saklamak
        self.last_checked = time.time()

    def check_and_block(self, src_ip):
        """
        Ağ trafiğini izler ve şüpheli IP'leri engeller.
        """
        current_time = time.time()

        # Eğer zaman penceresi (60 saniye) geçtiyse, aktiviteleri sıfırla
        if current_time - self.last_checked > self.time_window:
            self.reset_activity()

        # Bu IP için aktivite sayısını artır
        self.ip_activity[src_ip] += 1
        
        # Eğer IP'nin aktivite sayısı threshold'u (limit) aşarsa, IP'yi engelle
        if self.ip_activity[src_ip] > self.threshold:
            self.block_ip(src_ip)
        
    def reset_activity(self):
        """
        IP aktivitelerini sıfırlama fonksiyonu.
        """
        self.ip_activity.clear()
        self.last_checked = time.time()

    def block_ip(self, ip):
        """
        IP'yi engelleme fonksiyonu.
        """
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            print(f"IP Engellendi: {ip}")
            return ip  # Engellenen IP'yi döndür
        return None
