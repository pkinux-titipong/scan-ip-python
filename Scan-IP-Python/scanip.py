from scapy.all import ARP, Ether, srp
import argparse
import socket
import sys

def get_hostname(ip):
    """พยายามดึงชื่อโฮสต์จาก IP"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan_network(subnet):
    """ฟังก์ชันสแกนเครือข่ายและคืนค่าเป็นรายการของอุปกรณ์"""
    try:
        arp_request = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_request

        print(f"🔍 กำลังสแกนเครือข่าย: {subnet}...\n")
        result = srp(packet, timeout=2, verbose=False)[0]

        devices = []
        for sent, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "hostname": get_hostname(received.psrc)
            })
        
        return devices
    except Exception as e:
        print(f"❌ เกิดข้อผิดพลาด: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Network IP Scanner")
    parser.add_argument("subnet", help="กรุณากรอก IP และ Subnet (เช่น 192.168.1.0/24)")
    args = parser.parse_args()

    devices = scan_network(args.subnet)

    if devices:
        print("\nIP Address\t\tMAC Address\t\t\tHostname")
        print("-" * 60)
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}\t\t{device['hostname']}")
    else:
        print("⚠️ ไม่พบอุปกรณ์ในเครือข่าย")
    
    print("\n✅ Scan finished!!\n")

if __name__ == "__main__":
    main()
