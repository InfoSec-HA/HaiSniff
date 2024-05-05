from scapy.all import*
import socket
from geoip2 import geolite2

# def analyzer(pkt):
#     if pkt.haslayer(TCP):
#         print("-----------------------------------")
#         print("TCP Packet....")
#         scr_ip = pkt[IP].src
#         dst_ip = pkt[IP].dst
#         scr_mac = pkt.src
#         dst_mac = pkt.dst
#         scr_port = pkt.sport
#         dst_port = pkt.dport
#         print("SRC_IP : " + scr_ip)
#         print("DST_IP : " + dst_ip)
#         print("SRC_MAC : " + scr_ip)
#         print("DST_MAC : " + dst_ip)
#         print("SRC_PORT : " + str(scr_port))
#         print("DST_PORT : " + str(dst_port))
#         print("PACKET SIZE : " + str(len(pkt[TCP])))


#         if pkt.haslayer(ROW):
#             print(pkt[ROW].load)
        
       
#         print("-----------------------------------")
#     if pkt.haslayer(UDP):
#         print("-----------------------------------")
#         print("UDP Packet....")
#         scr_ip = pkt[IP].src
#         dst_ip = pkt[IP].dst
#         scr_mac = pkt.src
#         dst_mac = pkt.dst
#         scr_port = pkt.sport
#         dst_port = pkt.dport
#         print("SRC_IP : " + scr_ip)
#         print("DST_IP : " + dst_ip)
#         print("SRC_MAC : " + scr_ip)
#         print("DST_MAC : " + dst_ip)
#         print("SRC_PORT : " + str(scr_port))
#         print("DST_PORT : " + str(dst_port))
#         print("PACKET SIZE : " + str(len(pkt[UDP])))
#         if pkt.haslayer(ROW):
#             print(pkt[ROW].load)
#         print("-----------------------------------")
#         print("-----------------------------------")

def get_serv(src_port,dst_port):
    try:
        service = socket.getservbyport(src_port)
    except:
        service = socket.getservbyport(dst_port)
    return service

def locate(ip):
    loc = geolite2.lookup(ip)
    if loc is not None:
        return loc.country, loc.timezone
    else:
        return None
def analyzer(pkt):
    try:
        scr_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        loc_src = locate(scr_ip)
        loc_dst = locate(dst_ip)
        if loc_src is not None:
            country = loc_src[0]
            timezone = loc_src[1]
        elif loc_dst is not None:
            country = loc_dst[0]
            timezone = loc_dst[1]
        else:
            country = "Unknown"
            timezone = "Unknown"

        scr_mac = pkt.src
        dst_mac = pkt.dst
        if pkt.haslayer(ICMP):
            print("ICMP Packet....")
            print("SRC_IP : " + scr_ip)
            print("DST_IP : " + dst_ip)
            print("SRC_MAC : " + scr_ip)
            print("DST_MAC : " + dst_ip)
            print("TIMEZONE: " + timezone + "COUNTRY" + country)
            print("PACKET SIZE : " + str(len(pkt[ICMP])))
            if pkt.haslayer(ROW):
                print(pkt[ROW].load)
            print("-----------------------------------")
        else:
            scr_port = pkt.sport
            dst_port = pkt.dport
            service = get_serv(src_port, dst_port)
            if pkt.haslayer(TCP):
                print("TCP Packet....")
                print("SRC_IP : " + scr_ip)
                print("DST_IP : " + dst_ip)
                print("SRC_MAC : " + scr_ip)
                print("DST_MAC : " + dst_ip)
                print("SRC_PORT : " + str(scr_port))
                print("DST_PORT : " + str(dst_port))
                print("TIMEZONE: " + timezone + "COUNTRY" + country)
                print("PACKET SIZE : " + str(len(pkt[TCP])))
                if pkt.haslayer(ROW):
                    print(pkt[ROW].load)
                    print("-----------------------------------")
            if pkt.haslayer(UDP):
                print("UDP Packet....")
                print("SRC_IP : " + scr_ip)
                print("DST_IP : " + dst_ip)
                print("SRC_MAC : " + scr_ip)
                print("DST_MAC : " + dst_ip)
                print("SRC_PORT : " + str(scr_port))
                print("DST_PORT : " + str(dst_port))
                print("TIMEZONE: " + timezone + "COUNTRY" + country)
                print("PACKET SIZE : " + str(len(pkt[UDP])))
                if pkt.haslayer(ROW):
                    print(pkt[ROW].load)
                    print("-----------------------------------")    
    except:
        pass


print("Starting Captuer....") 
sniff(iface="wlan0", prn=analyzer)