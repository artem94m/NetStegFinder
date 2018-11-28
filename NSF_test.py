# -*- coding: utf-8 -*-
import socket
import struct
import sys

def make_ip(size, dscp, ecn, total_length, ident, flags, protocol, source_ip, dest_ip):
    packet_ver_and_ihl = (4 << 4) | size;
    packet_dscp_and_ecn = (dscp << 2) | ecn;
    packet_total_length = total_length;
    packet_ident = ident;
    packet_flags_and_offset = flags << 13;
    packet_ttl = 128;
    packet_protocol = protocol;
    packet_checksum = 0x0101; 
    packet_source_addr = socket.inet_aton(source_ip);
    packet_dest_addr = socket.inet_aton(dest_ip);

    if (size == 5):
        return struct.pack(
            '!BBHHHBBH4s4s', 
            packet_ver_and_ihl, packet_dscp_and_ecn, packet_total_length, 
            packet_ident, packet_flags_and_offset, 
            packet_ttl, packet_protocol, packet_checksum,
            packet_source_addr, packet_dest_addr
        );
    else:
        return struct.pack(
            '!BBHHHBBH4s4s' + '4s', 
            packet_ver_and_ihl, packet_dscp_and_ecn, packet_total_length, 
            packet_ident, packet_flags_and_offset, 
            packet_ttl, packet_protocol, packet_checksum,
            packet_source_addr, packet_dest_addr,
            "asdf"
        );


def make_icmp(ptype, code, ident, seq_number, data):
    packet_type = ptype;
    packet_code = code;
    packet_checksum = 0x0101; 
    packet_ident = ident;
    packet_seq_number = seq_number;
    packet_data = struct.pack("32s", data);

    return struct.pack(
        '!BBHHH32s', 
        packet_type, packet_code, packet_checksum,
        packet_ident, packet_seq_number,
        packet_data
    );
    
def make_tcp(source_port, dest_port, seq_number, ack_number, reserved, other_flags, flags, urg_pointer, data):
    packet_src_port = source_port;
    packet_dest_port = dest_port;
    packet_seq_number = seq_number;
    packet_ack_number = ack_number;
    packet_offset = (5 << 12) | (reserved << 9) | (other_flags << 6) | flags;
    packet_window_size = 0;
    packet_checksum = 0x0101;
    packet_urg_pointer = urg_pointer;
    packet_data = struct.pack("32s", data);

    return struct.pack(
        '!HHLLHHHH32s', 
        packet_src_port, packet_dest_port, packet_seq_number, packet_ack_number,
        packet_offset, packet_window_size, packet_checksum, packet_urg_pointer,
        packet_data
    );

                         
def make_udp(source_port, dest_port, data):
    packet_src_port = source_port;
    packet_dest_port = dest_port;
    packet_length = 40;
    packet_checksum = 0x0101;
    packet_data = struct.pack("32s", data);

    return struct.pack(
        '!HHHH32s', 
        packet_src_port, packet_dest_port,
        packet_length, packet_checksum, 
        packet_data
    );                       


def create_conn(s, host_number, category, steg_type):
    source_ip = "192.168.222." + str(host_number);
    dest_ip = "192.168.123.45";
    source_port = "";
    dest_port = "";
    packet = "";

    if (category == "HIGH"):
        if (steg_type == "1"):
            # IP неизвестный протокол
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 150, source_ip, dest_ip) + "0123456789";
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 150, dest_ip, source_ip) + "0123456789";
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 150, source_ip, dest_ip) + "0123456789";
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "2"):
            # IP ECN
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 2, 60, 1, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 1, 60, 2, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "3"):
            # IP Flags
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 5, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 5, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "4"):
            # ICMP Type
            source_port, dest_port = 0, 0;
            packet = make_ip(5, 0, 0, 60, 1, 0, 1, source_ip, dest_ip) + make_icmp(45, 0, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 1, dest_ip, source_ip) + make_icmp(44, 0, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 1, source_ip, dest_ip) + make_icmp(43, 0, 1, 2, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "5"):
            # ICMP Code
            source_port, dest_port = 0, 0;
            packet = make_ip(5, 0, 0, 60, 1, 0, 1, source_ip, dest_ip) + make_icmp(8, 33, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 1, dest_ip, source_ip) + make_icmp(0, 33, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 1, source_ip, dest_ip) + make_icmp(8, 33, 1, 2, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "6"):
            # ICMP Seq Number IN
            source_port, dest_port = 0, 0;
            packet = make_ip(5, 0, 0, 60, 1, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 45, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 1, dest_ip, source_ip) + make_icmp(0, 0, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 5, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "7"):
            # ICMP Seq Number OUT
            source_port, dest_port = 0, 0;
            packet = make_ip(5, 0, 0, 60, 1, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 1, dest_ip, source_ip) + make_icmp(0, 0, 1, 34, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 2, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 1, dest_ip, source_ip) + make_icmp(0, 0, 1, 5, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (source_ip, source_port));
        elif (steg_type == "8"):
            # ICMP Ident IN
            source_port, dest_port = 0, 0;
            packet = make_ip(5, 0, 0, 60, 1, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 5, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 1, dest_ip, source_ip) + make_icmp(0, 0, 5, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 2, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "9"):
            # ICMP Ident OUT
            source_port, dest_port = 0, 0;
            packet = make_ip(5, 0, 0, 60, 1, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 1, dest_ip, source_ip) + make_icmp(0, 0, 6, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 2, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 1, dest_ip, source_ip) + make_icmp(0, 0, 2, 2, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (source_ip, source_port));
        elif (steg_type == "10"):
            # TCP Reserved
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 123, 222, 5, 0, 48, 222, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 6, dest_ip, source_ip) + make_tcp(dest_port, source_port, 123, 222, 5, 0, 48, 222, "test");
            s.sendto(packet, (source_ip, source_port));
        elif (steg_type == "11"):
            # TCP URG Pointer
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 123, 222, 0, 0, 16, 222, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 6, dest_ip, source_ip) + make_tcp(dest_port, source_port, 123, 222, 0, 0, 16, 222, "test");
            s.sendto(packet, (source_ip, source_port));
        elif (steg_type == "12"):
            # TCP ACK Number
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 123, 222, 0, 0, 32, 222, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 6, dest_ip, source_ip) + make_tcp(dest_port, source_port, 123, 222, 0, 0, 32, 222, "test");
            s.sendto(packet, (source_ip, source_port));


    elif (category == "MEDIUM"):
        if (steg_type == "1"):
            # IP Options
            source_port, dest_port = 10000, 10001;
            packet = make_ip(6, 0, 0, 60, 1, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(6, 0, 0, 60, 2, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(6, 0, 0, 60, 3, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "2"):
            # IP DSCP
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 19, 0, 60, 1, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 23, 0, 60, 2, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 31, 0, 60, 3, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "3"):
            # ICMP Total Length
            source_port, dest_port = 0, 0;
            packet = make_ip(5, 0, 0, 60, 1, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 64, 2, 0, 1, dest_ip, source_ip) + make_icmp(0, 0, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F") + "0123";
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 68, 3, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 2, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F") + "01234567";
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "4"):
            # ICMP Data
            source_port, dest_port = 0, 0;
            packet = make_ip(5, 0, 0, 60, 1, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 1, "\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 1, dest_ip, source_ip) + make_icmp(0, 0, 1, 1, "\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 2, "\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "5"):
            # TCP Flags
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 123, 222, 0, 1, 48, 222, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 6, dest_ip, source_ip) + make_tcp(dest_port, source_port, 123, 222, 0, 1, 48, 222, "test");
            s.sendto(packet, (source_ip, source_port));
        elif (steg_type == "6"):
            # TCP Seq Number IN
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 234, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 6, dest_ip, source_ip) + make_tcp(dest_port, source_port, 12, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 123, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 6, dest_ip, source_ip) + make_tcp(dest_port, source_port, 12, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (source_ip, source_port));
        elif (steg_type == "7"):
            # TCP Seq Number OUT
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 12, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 6, dest_ip, source_ip) + make_tcp(dest_port, source_port, 543, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 12, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 6, dest_ip, source_ip) + make_tcp(dest_port, source_port, 123, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (source_ip, source_port));


    elif (category == "LOW"):
        if (steg_type == "1"):
            # TCP Source and Dest Ports, Source and Dest IP
            source_port, dest_port = 20000, 20001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 123, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "2"):
            # UDP Source and Dest Ports, Source and Dest IP
            source_port, dest_port = 20000, 20001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "3"):
            # IP последовательность IN
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 444, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2000, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 200, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 20, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
        elif (steg_type == "4"):
            # IP последовательность OUT
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 5, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2000, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 1221, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 253, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
        elif (steg_type == "5"):
            # TCP Suspicious Ports
            source_port, dest_port = 50000, 50001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 123, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 6, dest_ip, source_ip) + make_tcp(dest_port, source_port, 123, 222, 0, 0, 48, 222, "test");
            s.sendto(packet, (source_ip, source_port));
        elif (steg_type == "6"):
            # UDP Suspicious Ports
            source_port, dest_port = 50000, 50001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
    elif (category == "CLEAR"):
        if (steg_type == "1"):
            # CLEAR IP
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "2"):
            # CLEAR ICMP
            source_port, dest_port = 0, 0;
            packet = make_ip(5, 0, 0, 60, 1, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 1, dest_ip, source_ip) + make_icmp(0, 0, 1, 1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 1, source_ip, dest_ip) + make_icmp(8, 0, 1, 2, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F");
            s.sendto(packet, (dest_ip, dest_port));
        elif (steg_type == "3"):
            # CLEAR TCP
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 6, source_ip, dest_ip) + make_tcp(source_port, dest_port, 123, 0, 0, 0, 2, 0, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 6, dest_ip, source_ip) + make_tcp(dest_port, source_port, 123, 0, 0, 0, 2, 0, "test");
            s.sendto(packet, (source_ip, source_port));
        elif (steg_type == "4"):
            # CLEAR UDP
            source_port, dest_port = 10000, 10001;
            packet = make_ip(5, 0, 0, 60, 1, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));
            packet = make_ip(5, 0, 0, 60, 2, 0, 17, dest_ip, source_ip) + make_udp(dest_port, source_port, "test");
            s.sendto(packet, (source_ip, source_port));
            packet = make_ip(5, 0, 0, 60, 3, 0, 17, source_ip, dest_ip) + make_udp(source_port, dest_port, "test");
            s.sendto(packet, (dest_ip, dest_port));


def main():
    if (len(sys.argv) < 5):
        print "\nUsage: python nsf_test.py HIGH:1,2,2,6 MEDIUM:2,5 LOW:3,3 CLEAR:1,4";
        print "HIGH, MEDIUM, LOW, CLEAR - категории способов внедрения сетевой стеганографии";
        print "1,2,2,6 - номера конкретных методов внедрения информации";
        print "\nДля HIGH:";
        print "\t1 - Внедрение данных в поле \"Протокол\" IP-пакета";
        print "\t2 - Внедрение данных в поле \"ECN\" IP-пакета";
        print "\t3 - Внедрение данных в зарезервированный бит поля \"Флаги\" IP-пакета";
        print "\t4 - Внедрение данных в поле \"Тип\" ICMP-пакета";
        print "\t5 - Внедрение данных в поле \"Код\" ICMP-пакета";
        print "\t6 - Внедрение данных в поле \"Номер последовательности\" ICMP-пакета в исходящем потоке";
        print "\t7 - Внедрение данных в поле \"Номер последовательности\" ICMP-пакета во входящем потоке";
        print "\t8 - Внедрение данных в поле \"Идентификатор\" ICMP-пакета в исходящем потоке";
        print "\t9 - Внедрение данных в поле \"Идентификатор\" ICMP-пакета во входящем потоке";
        print "\t10 - Внедрение данных в зарезервированные биты TCP-пакета";
        print "\t11 - Внедрение данных в поле \"Указатель важности\" TCP-пакета";
        print "\t12 - Внедрение данных в поле \"Номер подтверждения\" TCP-пакета";
        print "\nДля MEDIUM:";
        print "\t1 - Внедрение данных в поле \"Опции\" IP-пакета";
        print "\t2 - Внедрение данных в поле \"DSCP\" IP-пакета";
        print "\t3 - Внедрение данных в ICMP-пакет за счет его размера";
        print "\t4 - Внедрение данных в поле \"Данные\" ICMP-пакета";
        print "\t5 - Внедрение данных в поле \"Флаги\" TCP-пакета";
        print "\t6 - Внедрение данных в поле \"Номер последовательности\" TCP-пакета в исходящем потоке";
        print "\t7 - Внедрение данных в поле \"Номер последовательности\" TCP-пакета во входящем потоке";
        print "\nДля LOW:";
        print "\t1 - Внедрение данных в поля IP-источника, IP-назначения, порт-источника, порт-назначения TCP-пакета";
        print "\t2 - Внедрение данных в поля IP-источника, IP-назначения, порт-источника, порт-назначения UDP-пакета";
        print "\t3 - Внедрение данных в поле \"Номер последовательности\" IP-пакета в исходящем потоке";
        print "\t4 - Внедрение данных в поле \"Номер последовательности\" IP-пакета во входящем потоке";
        print "\t5 - Внедрение данных за счет использования нестандартных портов TCP-пакета";
        print "\t6 - Внедрение данных за счет использования нестандартных портов UDP-пакета";
        print "\nДля CLEAR:";
        print "\t1 - Соединение без внедрения данных в IP-заголовке";
        print "\t2 - Соединение без внедрения данных в ICMP-заголовке";
        print "\t3 - Соединение без внедрения данных в TCP-заголовке";
        print "\t4 - Соединение без внедрения данных в UDP-заголовке";
        print "\nПри повторе номера метода, будет генерироваться другое соединение с тем же методом";
        print "Если нет необходимости в методах одной из категорий достаточно использовать подобную запись:";
        print "HIGH:0\n\n";

    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW);
        host_number = 1;
        methods = "";

        h_count = 0;
        m_count = 0;
        l_count = 0;
        c_count = 0;

        high_methods = sys.argv[1].split(":")[1];
        medium_methods = sys.argv[2].split(":")[1];
        low_methods = sys.argv[3].split(":")[1];
        clear_methods = sys.argv[4].split(":")[1];

        if (high_methods == "0"):
            pass;
        else:
            methods = high_methods.split(",");
            for m in methods:
                create_conn(s, host_number, "HIGH", m);
                h_count += 1;
                host_number += 1;

        if (medium_methods == "0"):
            pass;
        else:
            methods = medium_methods.split(",");
            for m in methods:
                create_conn(s, host_number, "MEDIUM", m);
                m_count += 1;
                host_number += 1;

        if (low_methods == "0"):
            pass;
        else:
            methods = low_methods.split(",");
            for m in methods:
                create_conn(s, host_number, "LOW", m);
                l_count += 1;
                host_number += 1;

        if (clear_methods == "0"):
            pass;
        else:
            methods = clear_methods.split(",");
            for m in methods:
                create_conn(s, host_number, "CLEAR", m);
                c_count += 1;
                host_number += 1;

        print "Сгенерировано соединений:";
        print "\tHIGH:", h_count;
        print "\tMEDIUM:", m_count;
        print "\tLOW:", l_count;
        print "\tCLEAR:", c_count;
        print "\tTOTAL:", host_number-1;

main();

