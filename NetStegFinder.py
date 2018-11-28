# -*- coding: utf-8 -*-

import sys
reload(sys)
sys.setdefaultencoding("utf-8")

from Tkinter import *
from ttk import Treeview
from ttk import Scrollbar
import threading
import socket
import struct
import os
import time
import hashlib

MAX_FRAME_SIZE = 65565;
ETH_P_ALL = 3;

class PACKET_STRUCT:
    
    def __init__(self, packet):
        self.direction = "";
        self.timestamp = int(time.time() * 1000000);

        self.eth_mac_dest = ":".join(x.encode("hex") for x in packet[0:6]); 
        self.eth_mac_src = ":".join(x.encode("hex") for x in packet[6:12]);
        self.eth_type = packet[12:14].encode("hex");
        packet = packet[14:];
        
        if (self.eth_type == "0800"):
            self.eth_type == "IP";
            
            ip_header = struct.unpack("!BBHHHBB2s4s4s", packet[0:20]);
            self.ip_version = ip_header[0] >> 4;
            self.ip_ihl = ip_header[0] & 0x0F;
            self.ip_dscp = ip_header[1] >> 2;
            self.ip_ecn = ip_header[1] & 0x03;
            self.ip_total_length = ip_header[2];
            self.ip_identification = ip_header[3];
            self.ip_flags = ip_header[4] >> 13;
            self.ip_frag_offset = ip_header[4] & 0x1FFF;
            self.ip_ttl = ip_header[5];
            self.ip_protocol = ip_header[6];
            self.ip_checksum = ip_header[7].encode("hex");
            self.ip_source_ip = socket.inet_ntoa(ip_header[8]);
            self.ip_dest_ip = socket.inet_ntoa(ip_header[9]);
            packet = packet[20:];
            
            if (self.ip_ihl > 5):
                options_size = (self.ip_ihl - 5) * 4;
                self.ip_options = packet[:options_size].encode("hex");
                packet = packet[options_size:];
                
            if (self.ip_protocol == 1):
                self.ip_protocol = "ICMP";
                
                icmp_header = struct.unpack("!BB2s", packet[0:4]);
                self.icmp_type = icmp_header[0];
                self.icmp_code = icmp_header[1];
                self.icmp_checksum = icmp_header[2].encode("hex");
                packet = packet[4:];
                
                if (self.icmp_type == 0 or self.icmp_type == 8):
                    echo_header = struct.unpack("!2sH8s", packet[0:12]);
                    self.icmp_ident = echo_header[0].encode("hex");
                    self.icmp_seq_numb = echo_header[1];
                    self.icmp_timestamp = echo_header[2].encode("hex");
                    packet = packet[12:];
                                
                self.icmp_data = packet.encode("hex");
                
            elif (self.ip_protocol == 6):
                self.ip_protocol = "TCP";
                                
                tcp_header = struct.unpack("!HHIIHH2sH", packet[0:20]);
                self.tcp_source_port = tcp_header[0];
                self.tcp_dest_port = tcp_header[1];
                self.tcp_seq_number = tcp_header[2];
                self.tcp_ack_number = tcp_header[3];
                self.tcp_data_offset = tcp_header[4] >> 12;
                self.tcp_reserved = (tcp_header[4] & 0x0E00) >> 9;
                self.tcp_other_flags = (tcp_header[4] & 0x01C0) >> 6;
                self.tcp_flags = tcp_header[4] & 0x003F;
                self.tcp_window_size = tcp_header[5];
                self.tcp_checksum = tcp_header[6].encode("hex");
                self.tcp_urg_pointer = tcp_header[7];
                packet = packet[20:];
                
                if (self.tcp_data_offset > 5):
                    options_size = (self.tcp_data_offset - 5) * 4;
                    self.tcp_options = packet[:options_size].encode("hex");
                    packet = packet[options_size:];
                
                if (packet == ""):
                    self.tcp_data = "None";
                else:
                    self.tcp_data = packet.encode("hex");
                            
            elif (self.ip_protocol == 17):
                self.ip_protocol = "UDP";
               
                udp_header = struct.unpack("!HHH2s", packet[0:8]);
                self.udp_source_port = udp_header[0];
                self.udp_dest_port = udp_header[1];
                self.udp_length = udp_header[2];
                self.udp_checksum = udp_header[3].encode("hex");
                packet = packet[8:];
                
                if (packet == ""):
                    self.udp_data = "None";
                else:
                    self.udp_data = packet.encode("hex");
            elif (self.ip_protocol < 143):
                self.ip_protocol = "UNSUPPORTED"

        else:
            self.eth_type = "NOT IP";

    def is_supported(self):
        if ((self.eth_type == "NOT IP") or (self.ip_protocol == "UNSUPPORTED")):
            return False;
        else:
            return True;
    
    def get_hash(self):
        in_packet = "";
        out_packet = "";
        
        if (self.ip_protocol == "TCP"):
            in_packet = self.ip_source_ip + self.ip_dest_ip + self.ip_protocol + str(self.tcp_source_port) + str(self.tcp_dest_port);
            out_packet = self.ip_dest_ip + self.ip_source_ip + self.ip_protocol + str(self.tcp_dest_port) + str(self.tcp_source_port);
        elif (self.ip_protocol == "UDP"):
            in_packet = self.ip_source_ip + self.ip_dest_ip + self.ip_protocol + str(self.udp_source_port) + str(self.udp_dest_port);
            out_packet = self.ip_dest_ip + self.ip_source_ip + self.ip_protocol + str(self.udp_dest_port) + str(self.udp_source_port);
        else:
            in_packet = self.ip_source_ip + self.ip_dest_ip + str(self.ip_protocol);
            out_packet = self.ip_dest_ip + self.ip_source_ip + str(self.ip_protocol);

        in_packet = hashlib.md5(in_packet).hexdigest();
        out_packet = hashlib.md5(out_packet).hexdigest();    
        
        self.in_hash = in_packet;
        self.out_hash = out_packet;
    
    def pretty_time(self): 
        milliseconds = str(int(self.timestamp))[-6:];
        main_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp/1000000));
    
        return main_date + "." + milliseconds;
   
class CONN:

    def __init__(self):
        self.category = "DEFAULT";
        self.status = "DEFAULT";
        self.count = 0;
        self.steg_field = "-";
        self.description = "Пусто";
        
        self.packets = [];

    def attach(self, packet):
        if (self.count == 0):
            self.in_hash = packet.in_hash;
            self.out_hash = packet.out_hash;
            self.source_ip = packet.ip_source_ip;
            self.dest_ip = packet.ip_dest_ip;
            self.proto = packet.ip_protocol;
            self.timestamp = packet.timestamp;

            if (self.proto == "TCP"):
                self.source_port = packet.tcp_source_port;
                self.dest_port = packet.tcp_dest_port;
            elif (self.proto == "UDP"):
                self.source_port = packet.udp_source_port;
                self.dest_port = packet.udp_dest_port;
            else:
                self.source_port = "-";
                self.dest_port = "-";
        
        if (self.count < 10):
            self.count += 1;
        else:
            del self.packets[0];

        if (self.in_hash == packet.in_hash):
            packet.direction = "INPUT";
        else:
            packet.direction = "OUTPUT";

        if (self.category == "CLEAR"):
            self.category = "DEFAULT";

        self.packets.append(packet);


class CONNECTIONS:
    
    def __init__(self):
        self.h_count = 0;
        self.m_count = 0;
        self.l_count = 0;
        self.o_count = 0
        
        self.cur_pack_src_ip = "-";
        self.cur_pack_dest_ip = "-";
        self.cur_pack_ident = "-";
        self.cur_pack_proto = "-";

        self.processed = 0;
        
        self.catalog = [];

    
    def process(self, packet):
        if (packet.is_supported()):
            packet.get_hash();
            self.processed += 1;

            self.cur_pack_src_ip = packet.ip_source_ip;
            self.cur_pack_dest_ip = packet.ip_dest_ip;
            self.cur_pack_ident = packet.ip_identification;
            self.cur_pack_proto = packet.ip_protocol;

            conn_number = self.found_conn(packet); 
            if (conn_number != -1):
                if (self.catalog[conn_number].category == "DEFAULT" or self.catalog[conn_number].category == "CLEAR"):
                    self.catalog[conn_number].attach(packet);
            else:
                self.create_conn(packet);

    def update_info(self):
        self.h_count = 0;
        self.m_count = 0;
        self.l_count = 0;
        self.o_count = 0;

        for conn in self.catalog:
            if (conn.category == "HIGH"):
                self.h_count += 1;
            elif (conn.category == "MEDIUM"):
                self.m_count += 1;
            elif (conn.category == "LOW"):
                self.l_count += 1;
            else:
                self.o_count += 1;

    def found_conn(self, packet):
        if (not self.catalog):
            return -1;
        else:
            for conn in self.catalog:
                if (set((conn.in_hash, conn.out_hash)) == set((packet.in_hash, packet.out_hash))):
                    return self.catalog.index(conn);

        return -1;             

    def create_conn(self, packet):
        new_conn = CONN();

        new_conn.attach(packet);
        self.catalog.append(new_conn);

        del new_conn;


class NSF_CORE():

    def __init__(self):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL));
            self.sock.settimeout(1);
        except socket.error, msg:
            print msg;
            sys.exit();

        self.conns = CONNECTIONS();

    def do_the_job(self, status, exit):
        while True:
            if (exit.is_set()):
                break;

            try:
                frame = self.sock.recv(MAX_FRAME_SIZE);
            except:
                continue;
            finally:
                self.scan();
                self.conns.update_info();

            if (status.is_set() == False):
                time.sleep(0.01);
            else:
                packet = PACKET_STRUCT(frame);
                        
                self.conns.process(packet);
                    
                del packet;
                   

    def scan(self):
        for conn in self.conns.catalog:
            if (conn.category == "DEFAULT" and conn.status != "EXCLUDED"):
                self.scan_ip(conn);

                if (conn.category == "HIGH"):
                   continue;

                if (conn.proto == "ICMP"):
                    self.scan_icmp(conn);
                elif (conn.proto == "TCP"):
                    self.scan_tcp(conn);
                elif (conn.proto == "UDP"):
                    self.scan_udp(conn);
                       
    def scan_ip(self, conn):
        # HIGH
        for packet in conn.packets:
            if (packet.ip_protocol != "ICMP" and packet.ip_protocol != "TCP" and packet.ip_protocol != "UDP" and packet.ip_protocol > 142):
                conn.category = "HIGH";
                conn.steg_field = "IP - Protocol";
                conn.description = "Внедрение данных с помощью неиспользуемых значений";
                return "HIGH";

            if (packet.ip_ecn != 0):
                conn.category = "HIGH";
                conn.steg_field = "IP - ECN";
                conn.description = "Внедрение данных в зарезервированные биты";
                return "HIGH";

            if ((packet.ip_flags >> 2) == 1):
                conn.category = "HIGH";
                conn.steg_field = "IP - Flags";
                conn.description = "Внедрение данных в зарезервированные биты";
                return "HIGH";

        # MEDIUM
        dscp_legal_values = (0, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 46, 48, 56);
        
        for packet in conn.packets:
            if (packet.ip_ihl > 5):
                conn.category = "MEDIUM";
                conn.steg_field = "IP - Options";
                conn.description = "Внедрение информации в поле \"Опции\"";
                return "MEDIUM";
            
            if (packet.ip_dscp not in dscp_legal_values):
                conn.category = "MEDIUM";
                conn.steg_field = "IP - DSCP";
                conn.description = "Внедрение информации в поле \"DSCP\"";
                return "MEDIUM";    

        # LOW
        prev_in_ident = -2;
        last_in_ident = -1;

        prev_out_ident = -2;
        last_out_ident = -1;

        for packet in conn.packets:
            if (packet.direction == "INPUT" and prev_in_ident > last_in_ident and last_in_ident > packet.ip_identification):
                conn.category = "LOW";
                conn.steg_field = "IP - Identification";
                conn.description = "Изменение порядка следования пакетов";
                return "LOW";
            elif (packet.direction == "INPUT"):
                prev_in_ident = last_in_ident;
                last_in_ident = packet.ip_identification;

            if (packet.direction == "OUTPUT" and prev_out_ident > last_out_ident and last_out_ident > packet.ip_identification):
                conn.category = "LOW";
                conn.steg_field = "IP - Identification";
                conn.description = "Изменение порядка следования пакетов";
                return "LOW";
            elif (packet.direction == "OUTPUT"):
                prev_out_ident = last_out_ident;
                last_out_ident = packet.ip_identification;
           
    def scan_icmp(self, conn):
        # HIGH
        prev_in_ident = 0;
        prev_out_ident = 0
        prev_in_seqnumb = 0;
        prev_out_seqnumb = 0;

        for packet in conn.packets:
            if (packet.icmp_type == 1 or packet.icmp_type == 2 or packet.icmp_type == 7 or (packet.icmp_type >= 19 and packet.icmp_type <= 29) or packet.icmp_type >= 41):
                conn.category = "HIGH";
                conn.steg_field = "ICMP - Type";
                conn.description = "Использование зарезервированных значений";
                return "HIGH";

            if (packet.icmp_code > 15):
                conn.category = "HIGH";
                conn.steg_field = "ICMP - Code";
                conn.description = "Использование зарезервированных значений";
                return "HIGH";

            if (packet.icmp_type == 0 or packet.icmp_type == 8):
                if (packet.direction == "INPUT"):
                    if (packet.icmp_ident == prev_in_ident):
                        if (packet.icmp_seq_numb < prev_in_seqnumb):
                            conn.category = "HIGH";
                            conn.steg_field = "ICMP - Seq Number";
                            conn.description = "Внедрение информации в поле \"Номер последовательности\"";
                            return "HIGH";
                        prev_in_seqnumb = packet.icmp_seq_numb;
                    elif (packet.icmp_ident > prev_in_ident):
                        prev_in_ident = packet.icmp_ident;
                        prev_in_seqnumb = packet.icmp_seq_numb;
                    else:
                        conn.category = "HIGH";
                        conn.steg_field = "ICMP - Identification";
                        conn.description = "Внедрение информации в поле \"Идентификатор\"";
                        return "HIGH";
                    prev_in_ident = packet.icmp_ident;

                if (packet.direction == "OUTPUT"):
                    if (packet.icmp_ident == prev_out_ident):
                        if (packet.icmp_seq_numb < prev_out_seqnumb):
                            conn.category = "HIGH";
                            conn.steg_field = "ICMP - Seq Number";
                            conn.description = "Внедрение информации в поле \"Номер последовательности\"";
                            return "HIGH";
                        prev_out_seqnumb = packet.icmp_seq_numb;
                    elif (packet.icmp_ident > prev_out_ident):
                        prev_out_ident = packet.icmp_ident;
                        prev_out_seqnumb = packet.icmp_seq_numb;
                    else:
                        conn.category = "HIGH";
                        conn.steg_field = "ICMP - Identification";
                        conn.description = "Внедрение информации в поле \"Идентификатор\"";
                        return "HIGH";
                    prev_out_ident = packet.icmp_ident;

        # MEDIUM
        prev_packet_length = conn.packets[0].ip_total_length;

        for packet in conn.packets:
            if (packet.ip_total_length != prev_packet_length):
                conn.category = "MEDIUM";
                conn.steg_field = "IP - Total Length";
                conn.description = "Передача скрытой информации засчет размера пакета";
                return "MEDIUM";

            if (packet.icmp_type == 8 or packet.icmp_type == 0):
                data_size = len(packet.icmp_data);
                sliced_data = struct.unpack("!HHHHH", packet.icmp_data[10:20]);
                found = 0;

                for i in xrange(0, len(sliced_data)-1):
                    if (sliced_data[i] >= sliced_data[i + 1]):
                        found = 1;
                        break;

                if (found == 1):
                    conn.category = "MEDIUM";
                    conn.steg_field = "ICMP - Data";
                    conn.description = "Внедрение информации в поле \"Данные\"";
                    return "MEDIUM";

    def scan_tcp(self, conn):
        # HIGH
        for packet in conn.packets:
            if (packet.tcp_reserved != 0):
                conn.category = "HIGH";
                conn.steg_field = "TCP - Reserved";
                conn.description = "Использование зарезервированных полей";
                return "HIGH";

            if (((packet.tcp_flags & 0x0020) >> 5) == 0 and packet.tcp_urg_pointer != 0):
                conn.category = "HIGH";
                conn.steg_field = "TCP - URG Pointer";
                conn.description = "Внедрение информации в поле \"Указатель важности\"";
                return "HIGH";

            if (((packet.tcp_flags & 0x0010) >> 4) == 0 and packet.tcp_ack_number != 0):
                conn.category = "HIGH";
                conn.steg_field = "TCP - ACK Number";
                conn.description = "Внедрение информации в поле \"Номер подтверждения\"";
                return "HIGH";

        # MEDIUM
        prev_in_seq_number = -1;
        prev_out_seq_number = -1;
        
        prev_in_tcp_ack_number = -1;
        prev_out_tcp_ack_number = -1;

        prev_in_packet_time = conn.timestamp;

        for packet in conn.packets:
            if (packet.tcp_other_flags != 0):
                conn.category = "MEDIUM";
                conn.steg_field = "TCP - Flags";
                conn.description = "Внедрение информации в поле \"Флаги\"";
                return "MEDIUM";

            if (packet.direction == "INPUT"):
                prev_in_tcp_ack_number = packet.tcp_ack_number;
            else:
                prev_out_tcp_ack_number = packet.tcp_ack_number;

            if (packet.direction == "INPUT" and packet.tcp_seq_number < prev_in_seq_number and (packet.tcp_seq_number != prev_out_tcp_ack_number and prev_out_tcp_ack_number != -1) and (packet.timestamp - prev_in_packet_time < 10000000)):
                conn.category = "MEDIUM";
                conn.steg_field = "TCP - Seq Number";
                conn.description = "Передача информации засчет изменения порядка пакетов";
                return "MEDIUM";
            elif (packet.direction == "INPUT"):
                prev_in_packet_time = packet.timestamp;
                prev_in_seq_number = packet.tcp_seq_number;

            if (packet.direction == "OUTPUT" and packet.tcp_seq_number < prev_out_seq_number and packet.tcp_seq_number != prev_in_tcp_ack_number and prev_in_seq_number != -1 and packet.tcp_ack_number != prev_in_seq_number):
                conn.category = "MEDIUM";
                conn.steg_field = "TCP - Seq Number";
                conn.description = "Передача информации засчет изменения порядка пакетов";
                return "MEDIUM";
            elif (packet.direction == "OUTPUT"):
                prev_out_seq_number = packet.tcp_seq_number;

        # LOW
        cur_time = int(time.time() * 1000000);

        if (conn.count == 1):
            if (cur_time - conn.packets[0].timestamp > 10000000):
                conn.category = "LOW";
                conn.steg_field = "TCP - Src и Dest Port, IP - Src и Dest Address";
                conn.description = "Внедрение информации засчет значения полей портов или адресов";
                return "LOW";
            else:
                conn.category = "DEFAULT";

        if (conn.source_port > 48654 and conn.dest_port > 48654 and conn.source_ip != "127.0.0.1" and conn.dest_ip != "127.0.0.1"):
            conn.category = "LOW";
            conn.steg_field = "TCP - Src и Dest Port";
            conn.description = "Использование подозрительных портов";
            return "LOW";

    def scan_udp(self, conn):
        # LOW
        cur_time = int(time.time() * 1000000);

        if (conn.count == 1):
            if (cur_time - conn.packets[0].timestamp > 10000000):
                conn.category = "LOW";
                conn.steg_field = "UDP - Src и Dest Port, IP - Src и Dest Address";
                conn.description = "Внедрение информации засчет значения полей портов или адресов";
                return "LOW";
            else: 
                conn.category = "DEFAULT";

        
        if (conn.source_port > 48654 and conn.dest_port > 48654 and conn.source_ip != "127.0.0.1" and conn.dest_ip != "127.0.0.1"):
            conn.category = "LOW";
            conn.steg_field = "UDP - Src и Dest Port";
            conn.description = "Использование подозрительных портов";
            return "LOW";



class NetStegFinder():
    
    def __init__(self):
        self.status = "stop";
        self.core = NSF_CORE();
        self.choosed_conn = "";

        self.th_status = threading.Event();
        self.th_exit = threading.Event();
        self.th_status.clear();
        self.th_exit.clear();
        self.thread = threading.Thread(target=self.core.do_the_job, args=(self.th_status, self.th_exit));
        self.thread.start();

        # Настройка окна
        self.root = Tk();
        
        self.root.title("NetStegFinder");
        self.place_to_center(self.root, 580, 370);
        self.root.resizable(0,0);
        self.root.configure(background="#e5e5e5");

        # Настройка меню
        self.menubar = Menu(self.root);
        self.menubar.add_command(label="Сохранить лог", command=lambda:self.save_log(self.core.conns.catalog));
        self.menubar.add_command(label="Выход", command=self.quit);
        self.root.config(menu=self.menubar);

        # Настройка элементов главного окна
        # Заголовок
        self.main_label = Label(self.root, text="Вероятность использования сетевой стеганографии:", fg="#444", bg="#e5e5e5", font="16");
        self.main_label.place(x=10, y=0, width=560, height=30);

        # Высокая вероятность
        self.high = Frame(self.root, bd=0, bg="#444");
        self.high_desc = Label(self.high, text="Высокая", fg="#fff", bg="#EF460C");
        self.high_desc.place(x=1, y=1, width=138, height=28);
        self.high_conn = Label(self.high, text="0 соединений", bg="#fff", fg="#444");
        self.high_conn.place(x=140, y=1, width=279, height=28);
        self.high_show = Button(self.high, text="Показать", bg="#00518d", fg="#fff", bd=0, activebackground="#003963", activeforeground="#fff", highlightthickness=0, command=lambda:self.show_category("HIGH"));
        self.high_show.place(x=419, y=0, width=141, height=30);
        self.high.place(x=10, y=35, width=560, height=30);

        # Средняя вероятность
        self.midd = Frame(self.root, bd=0, bg="#444");
        self.midd_desc = Label(self.midd, text="Средняя", fg="#fff", bg="#EF9E0C");
        self.midd_desc.place(x=1, y=1, width=138, height=28);
        self.midd_conn = Label(self.midd, text="0 соединений", bg="#fff", fg="#444");
        self.midd_conn.place(x=140, y=1, width=279, height=28);
        self.midd_show = Button(self.midd, text="Показать", bg="#00518d", fg="#fff", bd=0, activebackground="#003963", activeforeground="#fff", highlightthickness=0, command=lambda:self.show_category("MEDIUM"));
        self.midd_show.place(x=419, y=0, width=141, height=30);
        self.midd.place(x=10, y=75, width=560, height=30);

        # Низкая вероятность
        self.low = Frame(self.root, bd=0, bg="#444");
        self.low_desc = Label(self.low, text="Низкая", fg="#444", bg="#EFD30C");
        self.low_desc.place(x=1, y=1, width=138, height=28);
        self.low_conn = Label(self.low, text="0 соединений", bg="#fff", fg="#444");
        self.low_conn.place(x=140, y=1, width=279, height=28);
        self.low_show = Button(self.low, text="Показать", bg="#00518d", fg="#fff", bd=0, activebackground="#003963", activeforeground="#fff", highlightthickness=0, command=lambda:self.show_category("LOW"));
        self.low_show.place(x=419, y=0, width=141, height=30);
        self.low.place(x=10, y=115, width=560, height=30);

        # Остальные соединения
        self.other = Frame(self.root, bd=0, bg="#444");
        self.other_desc = Label(self.other, text="Остальные", fg="#fff", bg="#444");
        self.other_desc.place(x=1, y=1, width=138, height=28);
        self.other_conn = Label(self.other, text="0 соединений", bg="#fff", fg="#444");
        self.other_conn.place(x=140, y=1, width=279, height=28);
        self.other_show = Button(self.other, text="Показать", bg="#00518d", fg="#fff", bd=0, activebackground="#003963", activeforeground="#fff", highlightthickness=0, command=lambda:self.show_category("OTHER"));
        self.other_show.place(x=419, y=0, width=141, height=30);
        self.other.place(x=10, y=155, width=560, height=30);

        # Сканируемый пакет
        self.scan = Frame(self.root, bd=0, bg="#444");
        self.scan_desc = Label(self.scan, text="   Последний пакет: ", fg="#444", bg="#f1f1f1", anchor=W);
        self.scan_desc.place(x=1, y=1, width=558, height=28);

        self.scan_title_ipscr = Label(self.scan, text="IP Источника", fg="#444", bg="#f1f1f1");
        self.scan_title_ipscr.place(x=1, y=30, width=138, height=24);
        self.scan_title_ipdest = Label(self.scan, text="IP Назначения", fg="#444", bg="#f1f1f1");
        self.scan_title_ipdest.place(x=140, y=30, width=139, height=24);
        self.scan_title_ipident = Label(self.scan, text="Идентификатор", fg="#444", bg="#f1f1f1");
        self.scan_title_ipident.place(x=280, y=30, width=139, height=24);
        self.scan_title_ipproto = Label(self.scan, text="Протокол", fg="#444", bg="#f1f1f1");
        self.scan_title_ipproto.place(x=420, y=30, width=139, height=24);
        
        self.scan_ipscr = Label(self.scan, text="-", fg="#444", bg="#fff");
        self.scan_ipscr.place(x=1, y=55, width=138, height=24);
        self.scan_ipdest = Label(self.scan, text="-", fg="#444", bg="#fff");
        self.scan_ipdest.place(x=140, y=55, width=139, height=24);
        self.scan_ipident = Label(self.scan, text="-", fg="#444", bg="#fff");
        self.scan_ipident.place(x=280, y=55, width=139, height=24);
        self.scan_ipproto = Label(self.scan, text="-", fg="#444", bg="#fff");
        self.scan_ipproto.place(x=420, y=55, width=139, height=24);

        # Всего отсканировано
        self.scan_total = Label(self.scan, text="Всего пакетов: 0", fg="#444", bg="#e5e5e5", anchor=E);
        self.scan_total.place(x=0, y=80, width=560, height=30);
        self.scan.place(x=10, y=205, width=560, height=110);

        # Управляющие кнопки
        self.control = Frame(self.root, bd=0, bg="#e5e5e5");
        self.control_start = Button(self.control, text="Сканировать", bg="#008d2d", fg="#fff", bd=0, activebackground="#005C1C", highlightthickness=0, activeforeground="#fff", command=lambda:self.change_status("run"));
        self.control_start.place(x=170, y=0, width=100, height=30);
        self.control_stop = Button(self.control, text="Остановить", bg="#6d6d6d", fg="#fff", bd=0, activebackground="#454545", highlightthickness=0, activeforeground="#fff", command=lambda:self.change_status("stop"));
        self.control_stop.place(x=290, y=0, width=100, height=30);
        self.control.place(x=10, y=330, width=560, height=30);

        self.update_info();

        self.root.protocol("WM_DELETE_WINDOW", self.quit);
        self.root.mainloop();

    def quit(self):
        self.th_exit.set();
        self.core.sock.close();
        self.root.destroy();
        self.root.quit();

    def save_log(self, conns):
        filename = "NSF_LOG_" + time.strftime("%Y-%m-%d_%H-%M-%S.txt");
        log = open(filename, 'w+');
        
        log.write("Лог NetStegFinder за " + time.strftime("%Y.%m.%d %H:%M:%S \n"));
        log.write("----------------------------------------");
        log.write("\n\nВысокая вероятность наличия сетевой стеганографии:\n");
        log.write('%-16s%16s%16s%16s%20s%50s%65s%10s\n' % ('IP Источника'.decode("utf-8"), 'IP Назначения'.decode("utf-8"), 'Протокол'.decode("utf-8"), 'Порт источника'.decode("utf-8"), 'Порт назначения'.decode("utf-8"), 'Поле'.decode("utf-8"), 'Тип стеганографии'.decode("utf-8"), 'Статус'.decode("utf-8")));
        for conn in conns:
            if (conn.category == "HIGH"):
                log.write('%-16s%16s%16s%16s%20s%50s%65s%10s\n' % (str(conn.source_ip).decode("utf-8"), str(conn.dest_ip).decode("utf-8"), str(conn.proto).decode("utf-8"), str(conn.source_port).decode("utf-8"), str(conn.dest_port).decode("utf-8"), str(conn.steg_field).decode("utf-8"), str(conn.description).decode("utf-8"), str(conn.status).decode("utf-8")));
        
        log.write("\n\nСредняя вероятность наличия сетевой стеганографии:\n");
        log.write('%-16s%16s%16s%16s%20s%50s%65s%10s\n' % ('IP Источника'.decode("utf-8"), 'IP Назначения'.decode("utf-8"), 'Протокол'.decode("utf-8"), 'Порт источника'.decode("utf-8"), 'Порт назначения'.decode("utf-8"), 'Поле'.decode("utf-8"), 'Тип стеганографии'.decode("utf-8"), 'Статус'.decode("utf-8")));
        for conn in conns:
            if (conn.category == "MEDIUM"):
                log.write('%-16s%16s%16s%16s%20s%50s%65s%10s\n' % (str(conn.source_ip).decode("utf-8"), str(conn.dest_ip).decode("utf-8"), str(conn.proto).decode("utf-8"), str(conn.source_port).decode("utf-8"), str(conn.dest_port).decode("utf-8"), str(conn.steg_field).decode("utf-8"), str(conn.description).decode("utf-8"), str(conn.status).decode("utf-8")));
        
        log.write("\n\nНизкая вероятность наличия сетевой стеганографии:\n");
        log.write('%-16s%16s%16s%16s%20s%50s%65s%10s\n' % ('IP Источника'.decode("utf-8"), 'IP Назначения'.decode("utf-8"), 'Протокол'.decode("utf-8"), 'Порт источника'.decode("utf-8"), 'Порт назначения'.decode("utf-8"), 'Поле'.decode("utf-8"), 'Тип стеганографии'.decode("utf-8"), 'Статус'.decode("utf-8")));
        for conn in conns:
            if (conn.category == "LOW"):
                log.write('%-16s%16s%16s%16s%20s%50s%65s%10s\n' % (str(conn.source_ip).decode("utf-8"), str(conn.dest_ip).decode("utf-8"), str(conn.proto).decode("utf-8"), str(conn.source_port).decode("utf-8"), str(conn.dest_port).decode("utf-8"), str(conn.steg_field).decode("utf-8"), str(conn.description).decode("utf-8"), str(conn.status).decode("utf-8")));
        
        log.write("\n\nОстальные соединения:\n");
        log.write('%-16s%16s%16s%16s%20s%50s%65s%10s\n' % ('IP Источника'.decode("utf-8"), 'IP Назначения'.decode("utf-8"), 'Протокол'.decode("utf-8"), 'Порт источника'.decode("utf-8"), 'Порт назначения'.decode("utf-8"), 'Поле'.decode("utf-8"), 'Тип стеганографии'.decode("utf-8"), 'Статус'.decode("utf-8")));
        for conn in conns:
            if (conn.category != "LOW" and conn.category != "MEDIUM" and conn.category != "HIGH"):
                log.write('%-16s%16s%16s%16s%20s%50s%65s%10s\n' % (str(conn.source_ip).decode("utf-8"), str(conn.dest_ip).decode("utf-8"), str(conn.proto).decode("utf-8"), str(conn.source_port).decode("utf-8"), str(conn.dest_port).decode("utf-8"), str(conn.steg_field).decode("utf-8"), str(conn.description).decode("utf-8"), str(conn.status).decode("utf-8")));
        
        log.close();

    def place_to_center(self, window, width, height):
        screen_width = window.winfo_screenwidth();
        screen_height = window.winfo_screenheight();
        pos_x = (screen_width/2) - (width/2);
        pos_y = (screen_height/2) - (height/2);
        window.minsize(width, height);
        window.geometry("%dx%d+%d+%d" % (width, height, pos_x, pos_y));

    def show_category(self, category):
        self.title = "";
        self.bg_color = "";
        self.fg_color = "";
        self.categ = category;

        if (category == "HIGH"):
            self.title = "Высокая вероятность";
            self.bg_color = "#EF460C";
            self.fg_color = "#fff";
        elif (category == "MEDIUM"):
            self.title = "Средняя вероятность";
            self.bg_color = "#EF9E0C";
            self.fg_color = "#fff";
        elif (category == "LOW"):
            self.title = "Низкая вероятность";
            self.bg_color = "#EFD30C";
            self.fg_color = "#444";
        else:
            self.title = "Остальные соединения"
            self.bg_color = "#e5e5e5";
            self.fg_color = "#444";

        self.child_window = Toplevel();
        self.child_window.title("NetStegFinder - " + self.title);
        self.place_to_center(self.child_window, 850, 300);
        self.child_window.configure(background="#e5e5e5");
        self.child_window.grab_set();

        self.category_name = Label(self.child_window, text=self.title, fg=self.fg_color, bg=self.bg_color, font="16");
        self.category_name.place(relx=0.02, rely=0.02, relwidth=0.96, relheight=0.1);

        self.conns = Frame(self.child_window, bd=0, bg="#e5e5e5");

        self.connections = Treeview(self.conns, selectmode="extended", columns=("ip_src", "ip_dest", "proto", "port_src", "port_dest", "field", "type_of_steg", "status"), show="headings");
        self.connections.heading("ip_src", text="IP Источника", anchor="center");
        self.connections.heading("ip_dest", text="IP Назначения", anchor="center");
        self.connections.heading("proto", text="Протокол", anchor="center");
        self.connections.heading("port_src", text="Порт источника", anchor="center");
        self.connections.heading("port_dest", text="Порт назначения", anchor="center");
        self.connections.heading("field", text="Поле", anchor="center");
        self.connections.heading("type_of_steg", text="Тип стеганографии", anchor="center");
        self.connections.heading("status", text="Статус", anchor="center");
        
        self.connections.column("#1", width=120, minwidth=120, stretch=YES);
        self.connections.column("#2", width=120, minwidth=120, stretch=YES);
        self.connections.column("#3", width=100, minwidth=100, stretch=YES);
        self.connections.column("#4", width=120, minwidth=120, stretch=YES);
        self.connections.column("#5", width=130, minwidth=130, stretch=YES);
        self.connections.column("#6", width=300, minwidth=300, stretch=YES);
        self.connections.column("#7", width=540, minwidth=540, stretch=YES);
        self.connections.column("#8", width=100, minwidth=100, stretch=YES);
       
        self.vert_scrollbar = Scrollbar(self.conns, orient="vertical", command=self.connections.yview);
        self.hor_scrollbar = Scrollbar(self.conns, orient="horizontal", command=self.connections.xview);
        self.vert_scrollbar.pack(side=RIGHT, fill=Y);
        self.hor_scrollbar.pack(side=BOTTOM, fill=X);
        self.connections.configure(yscrollcommand=self.vert_scrollbar.set, xscrollcommand=self.hor_scrollbar.set);
        self.connections.bind("<ButtonRelease-1>", self.selected_item);
        self.connections.pack(side=LEFT, fill=BOTH, expand=1);

        self.conns.place(relx=0.02, rely=0.14, relwidth=0.96, relheight=0.72);

        self.control_cat = Frame(self.child_window, bd=0, bg="#e5e5e5");
        self.control_block = Button(self.control_cat, text="Блокировать", bg="#8d0000", fg="#fff", bd=0, highlightthickness=0, activebackground="#5c0000", activeforeground="#fff", command=lambda:self.action("block"));
        self.control_block.place(relx=0.35, rely=0.0, relwidth=0.12, relheight=1.0);
        self.control_exclude = Button(self.control_cat, text="Исключить", bg="#008d2d", fg="#fff", bd=0, highlightthickness=0, activebackground="#005C1C", activeforeground="#fff", command=lambda:self.action("excluded"));
        self.control_exclude.place(relx=0.53, rely=0.0, relwidth=0.12, relheight=1.0);
        self.control_cat.place(relx=0.02, rely=0.88, relwidth=0.96, relheight=0.1);

        self.update_category();
        
        self.child_window.mainloop();

    def update_category(self):
        self.connections.tag_configure("BLOCKED", background="#989898", foreground="#fff");
        self.connections.tag_configure("EXCLUDED", background="#45ae00", foreground="#fff");
        self.connections.tag_configure("DEFAULT", background="#fff", foreground="#000");

        self.connections.delete(*self.connections.get_children());
        for conn in self.core.conns.catalog:
            if (conn.category == self.categ):
                self.connections.insert("", "end", tags=(conn.status,), values=(conn.source_ip, conn.dest_ip, conn.proto, conn.source_port, conn.dest_port, conn.steg_field, conn.description, conn.status, conn.in_hash));
            elif (self.categ == "OTHER"):
                if (conn.category == "DEFAULT" or conn.category == "CLEAR"):
                    self.connections.insert("", "end", tags=(conn.status,), values=(conn.source_ip, conn.dest_ip, conn.proto, conn.source_port, conn.dest_port, conn.steg_field, conn.description, conn.status, conn.in_hash));

    def selected_item(self, event):
        cur_item = self.connections.selection();
        conn_values = self.connections.item(cur_item)["values"];
        if (conn_values):
            conn_data = conn_values[0] + conn_values[1] + str(conn_values[2]);
            if (conn_values[2] != "ICMP" and not str(conn_values[2]).isdigit()):
                conn_data = conn_data + str(conn_values[3]) + str(conn_values[4]);
            self.choosed_conn = hashlib.md5(conn_data).hexdigest();
          
    def action(self, act):
        new_status = "";
        ctarget = " > /dev/null 2>&1";
        clear = "iptables -D"; 
        add = "iptables -A";
        target = "";
        sip = "";
        dip = "";
        rsip = "";
        rdip = "";
        proto = "";
        sport = "";
        dport = "";
        rsport = "";
        rdport = "";

        if (act == "block"):
            new_status = "BLOCKED";
            target = " -j DROP > /dev/null 2>&1";
        else:
            new_status = "EXCLUDED";
            target = " -j ACCEPT > /dev/null 2>&1";        

        for conn in self.core.conns.catalog:
            if (conn.in_hash == self.choosed_conn):
                conn.status = new_status;
                sip = " -s " + conn.source_ip;
                dip = " -d " + conn.dest_ip;
                rsip = " -s " + conn.dest_ip;
                rdip = " -d " + conn.source_ip;
                if (conn.proto == "UDP" or conn.proto == "TCP"):
                    proto = " -p " + conn.proto.lower();
                    sport = " --sport " + str(conn.source_port);
                    dport = " --dport " + str(conn.dest_port);
                    rsport = " --sport " + str(conn.dest_port);
                    rdport = " --dport " + str(conn.source_port);
                elif (conn.proto == "ICMP"):
                    proto = " -p icmp ";
                else:
                    proto = " -p all ";
                break;

        os.system(clear + " OUTPUT " + sip + dip + proto + sport + dport + " -j DROP " + ctarget);
        os.system(clear + " OUTPUT " + rsip + rdip + proto + rsport + rdport + " -j DROP " + ctarget);
        os.system(clear + " INPUT " + sip + dip + proto + sport + dport + " -j DROP " + ctarget);
        os.system(clear + " INPUT " + rsip + rdip + proto + rsport + rdport + " -j DROP " + ctarget);
        os.system(clear + " FORWARD " + sip + dip + proto + sport + dport + " -j DROP " + ctarget);
        os.system(clear + " FORWARD " + rsip + rdip + proto + rsport + rdport + " -j DROP " + ctarget);
        
        os.system(clear + " OUTPUT " + sip + dip + proto + sport + dport + " -j ACCEPT " + ctarget);
        os.system(clear + " OUTPUT " + rsip + rdip + proto + rsport + rdport + " -j ACCEPT " + ctarget);
        os.system(clear + " INPUT " + sip + dip + proto + sport + dport + " -j ACCEPT " + ctarget);
        os.system(clear + " INPUT " + rsip + rdip + proto + rsport + rdport + " -j ACCEPT " + ctarget);
        os.system(clear + " FORWARD " + sip + dip + proto + sport + dport + " -j ACCEPT " + ctarget);
        os.system(clear + " FORWARD " + rsip + rdip + proto + rsport + rdport + " -j ACCEPT " + ctarget);

        os.system(add + " OUTPUT " + sip + dip + proto + sport + dport + target);
        os.system(add + " OUTPUT " + rsip + rdip + proto + rsport + rdport + target);
        os.system(add + " INPUT " + sip + dip + proto + sport + dport + target);
        os.system(add + " INPUT " + rsip + rdip + proto + rsport + rdport + target);
        os.system(add + " FORWARD " + sip + dip + proto + sport + dport + target);
        os.system(add + " FORWARD " + rsip + rdip + proto + rsport + rdport + target);

        self.update_category();

    def change_status(self, stat):
        self.status = stat;
        
        if (stat == "run"):
            self.th_status.set();
        else:
            self.th_status.clear();

    def update_info(self):
        if (self.status == "run"):
            self.high_conn.configure(text=str(self.core.conns.h_count)+" соединений");
            self.midd_conn.configure(text=str(self.core.conns.m_count)+" соединений"); 
            self.low_conn.configure(text=str(self.core.conns.l_count)+" соединений");
            self.other_conn.configure(text=str(self.core.conns.o_count)+" соединений");

            self.scan_ipscr.configure(text=self.core.conns.cur_pack_src_ip);
            self.scan_ipdest.configure(text=self.core.conns.cur_pack_dest_ip);
            self.scan_ipident.configure(text=self.core.conns.cur_pack_ident);
            self.scan_ipproto.configure(text=self.core.conns.cur_pack_proto);
        
            self.scan_total.configure(text="Всего пакетов: "+str(self.core.conns.processed));

        self.root.after(100, self.update_info);

app = NetStegFinder();
