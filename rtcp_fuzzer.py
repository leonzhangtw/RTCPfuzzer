#!/usr/bin/python
# -*- coding: utf-8 -*-
# from scapy.all import *
import socket
import os
import time
import hashlib
import string
import random
from itertools import islice, product, chain
from bitstring import BitArray
from ConfigParser import ConfigParser
import sys

#global varible
config = ConfigParser()
config.read('rtcp.conf')
RHOST = config.get('rtcpfuzz', 'RHOST')
RPORT = config.get('rtcpfuzz', 'RPORT')
DELAY = config.get('rtcpfuzz', 'DELAY')
junk = config.get('rtcpfuzz', 'JUNK')
msfpat = config.get('rtcpfuzz', 'MSFPATTERN')
STOPAFTER = config.get('rtcpfuzz', 'STOPAFTER')
SERVICETYPE = config.get('rtcpfuzz', 'TYPE')
# Little Bit Typecasting
RPORT = int(RPORT)
STOPAFTER = int(STOPAFTER)
DELAY = int(DELAY)
TEST_CASE_ID = 0

rtcp_packet_types = {
    'version': 2,
    'padding': 0,
    'crsc_count': 0,
    'extension': 0,
    'marker': 0,
    'payload_type': 99,
    'sequence_number': 16,
    'timev': 32,
    'ssrc_id': 3000,
    'csrc_id': 32,
    'profile_extension_id': 16,
    'extension_header_length': 16,
    'payload': -1
}

# RR packet format declaration
# rc means "Reception report count"
# lsr means "last SR"
# dlsr means "delay since last SR"
rtcp_RR_types = {
    'version': 2, # 2 bits
    'padding': 0, # 1 bits
    'rc': 0,      # 5 bits
    'packet_type': 201, # 8 bits
    'length' : 32,      # 16 bits
    'ssrc_sender': 32,  # 32 bits
    'fraction_lost': 32,# 8 bits
    'cumulative_packet_loss': 3000, # 24 bits
    'extended_highest_sequence_number': 32, # 32 bits
    'interarrival_jitter': 16, # 32 bits
    'lsr': 16, # 32 bits
    'dlsr': 16             # 32 bits
}

# SR packet format declaration
# rc means "Reception report count"
# lsr means "last SR"
# dlsr means "delay since last SR"
rtcp_SR_types = {
    'version' : 2, # 2 bits
    'padding' : 0, # 1 bits
    'rc' : 0,      # 5 bits
    'packet_type' : 200, # 8 bits
    'length' : 32,      # 16 bits
    'ssrc_sender' : 32,  # 32 bits
    'ntp_timestamp_MSW' : 30000, #32 bits
    'ntp_timestamp_LSW' : 50000 , #32 bits
    'rtp_timestamp' : 100000,# 32 bits
    'sender_packet_count' : 300, # 32 bits
    'sender_octet_count' : 33333, # 32bits
    'fraction_lost': 32,  # 8 bits
    'cumulative_packet_loss': 3000,  # 24 bits
    'extended_highest_sequence_number': 32,  # 32 bits
    'interarrival_jitter': 16,  # 32 bits
    'lsr': 16,  # 32 bits
    'dlsr': -1  # 32 bits
}

# SDES(source description) packet format declaration
# sc means "source count"
# lsr means "last SR"
# dlsr means "delay since last SR"
rtcp_SDES_types = {
    'version': 2,  # 2 bits
    'padding': 0,  # 1 bits
    'sc': 0,  # 5 bits
    'packet_type': 202,  # 8 bits
    'length': 32,  # 16 bits
    'ssrc_csrc_id': 32,  # 32 bits
    'cname': 1,  # 8 bits
    'cname_length': 8,  # 8 bits
    'cname_domain': 'QQQQQQQ',  # not define size
}

def createpattern(length):
    length = int(length)
    data = ''.join(tuple(islice(chain.from_iterable(product(
        string.ascii_uppercase, string.ascii_lowercase, string.digits)), length)))
    return data


def send_to_target(data):

    # data += createpattern(100)
    try:

        if SERVICETYPE == 'TCP':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((RHOST, RPORT))
            s.send(data)
            time.sleep(DELAY)

        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(data, (RHOST, RPORT))
            time.sleep(DELAY)

        print("[*] Test case ID:%d" % (TEST_CASE_ID) + " END------")

    except:
        print('ERROR: Build Socket failed,Check Service is TCP or UDP !!!')
        sys.exit(1)

def fuzz_payloadtype(count):
    global  TEST_CASE_ID
    for i in range(count):

        rtcp_packet = BitArray()
        rtcp_packet += 'uint:2=%d' % rtcp_packet_types['version']
        rtcp_packet += 'uint:1=%d' % rtcp_packet_types['padding']
        rtcp_packet += 'uint:1=%d' % rtcp_packet_types['extension']
        rtcp_packet += 'uint:4=%d' % rtcp_packet_types['crsc_count']
        rtcp_packet += 'uint:1=%d' % rtcp_packet_types['marker']
        # payload type range
        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        print("[*] Test type : Basis Payloadtype, Payload : %d " %(i))
        rtcp_packet += 'uint:7=%d' % i
        rtcp_packet += 'uint:16=%d' % rtcp_packet_types['sequence_number']
        rtcp_packet += 'uint:32=%d' % rtcp_packet_types['timev']
        rtcp_packet += 'uint:32=%d' % rtcp_packet_types['ssrc_id']
        send_to_target(rtcp_packet.tobytes())
def fuzz_timestamp(count):
    global  TEST_CASE_ID
    for i in range(count):

        rtcp_packet = BitArray()
        rtcp_packet += 'uint:2=%d' % rtcp_packet_types['version']
        rtcp_packet += 'uint:1=%d' % rtcp_packet_types['padding']
        rtcp_packet += 'uint:1=%d' % rtcp_packet_types['extension']
        rtcp_packet += 'uint:4=%d' % rtcp_packet_types['crsc_count']
        rtcp_packet += 'uint:1=%d' % rtcp_packet_types['marker']
        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        print("[*] payloadtype test: %d " %(i))
        rtcp_packet += 'uint:7=%d' % i
        # rtcp_packet += 'uint:16=%d' % rtcp_packet_types['sequence_number']
        rtcp_packet += 'uint:16=%d' % 30000
        rtcp_packet += 'uint:32=%d' % rtcp_packet_types['timev']
        rtcp_packet += 'uint:32=%d' % rtcp_packet_types['ssrc_id']
        send_to_target(rtcp_packet.tobytes())

def fuzz_SR_SDES_packet_basis(count):
    global TEST_CASE_ID
    ssrc_id_max = 2 ** 32 - 1
    for i in range(count):
        sr_sdes_packet = BitArray()
        rtcp_SR_types['length'] = 6
        sr_sdes_packet += 'uint:2=%d' % rtcp_SR_types['version']
        sr_sdes_packet += 'uint:1=%d' % rtcp_SR_types['padding']
        sr_sdes_packet += 'uint:5=%d' % rtcp_SR_types['rc']
        sr_sdes_packet += 'uint:8=%d' % rtcp_SR_types['packet_type']
        sr_sdes_packet += 'uint:16=%d' % rtcp_SR_types['length']

        rand_ssrc_id = random.randint(0, ssrc_id_max)
        rand_ntp_timestamp_MSL = random.randint(0, ssrc_id_max)
        rand_ntp_timestamp_LSW = random.randint(0, ssrc_id_max)
        rand_rtp_timestamp = random.randint(0, ssrc_id_max)
        rand_ntp_timestamp_LSW = random.randint(0, ssrc_id_max)
        rand_sender_packet_count = random.randint(0, ssrc_id_max)
        rand_sender_octet_count = random.randint(0, ssrc_id_max)

        sr_sdes_packet += 'uint:32=%d' % rand_ssrc_id
        sr_sdes_packet += 'uint:32=%d' % rand_ntp_timestamp_MSL
        sr_sdes_packet += 'uint:32=%d' % rand_ntp_timestamp_LSW
        sr_sdes_packet += 'uint:32=%d' % rand_rtp_timestamp
        sr_sdes_packet += 'uint:32=%d' % rand_sender_packet_count
        sr_sdes_packet += 'uint:32=%d' % rand_sender_octet_count

        print("[*] Test case ID:%d" % (TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        print("[*] Test type : Basis SR_SDES packet mix fuzzing Test ")

        # SDES packet part
        rtcp_SDES_types['length'] = 6
        sr_sdes_packet += 'uint:2=%d' % rtcp_SDES_types['version']
        sr_sdes_packet += 'uint:1=%d' % rtcp_SDES_types['padding']
        sr_sdes_packet += 'uint:5=%d' % rtcp_SDES_types['sc']
        sr_sdes_packet += 'uint:8=%d' % rtcp_SDES_types['packet_type']
        sr_sdes_packet += 'uint:16=%d' % rtcp_SDES_types['length']
        sr_sdes_packet += 'uint:32=%d' % rtcp_SDES_types['ssrc_csrc_id']
        sr_sdes_packet += 'uint:8=%d' % rtcp_SDES_types['cname']
        domain = 'DeloitteTestSR'
        rtcp_SDES_types['cname_length'] = len(domain)
        sr_sdes_packet += 'uint:8=%d' % rtcp_SDES_types['cname_length']
        send_to_target(sr_sdes_packet.tobytes()+domain+'\x00')


def fuzz_SR_packet_basis(count):
    global  TEST_CASE_ID
    ssrc_id_max = 2**32 - 1
    for i in range(count):
        sr_packet = BitArray()
        rtcp_SR_types['length'] = 6
        sr_packet += 'uint:2=%d' % rtcp_SR_types['version']
        sr_packet += 'uint:1=%d' % rtcp_SR_types['padding']
        sr_packet += 'uint:5=%d' % rtcp_SR_types['rc']
        sr_packet += 'uint:8=%d' % rtcp_SR_types['packet_type']
        sr_packet += 'uint:16=%d' % rtcp_SR_types['length']
        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        rand_ssrc_id = random.randint(0,ssrc_id_max)
        rand_ntp_timestamp_MSL = random.randint(0,ssrc_id_max)
        rand_ntp_timestamp_LSW = random.randint(0,ssrc_id_max)
        rand_rtp_timestamp = random.randint(0,ssrc_id_max)
        rand_ntp_timestamp_LSW = random.randint(0,ssrc_id_max)
        rand_sender_packet_count = random.randint(0,ssrc_id_max)
        rand_sender_octet_count = random.randint(0,ssrc_id_max)

        print("[*] Test type : Basis SR packet mix fuzzing Test , Payload : %d " %(rand_ssrc_id))
        sr_packet += 'uint:32=%d' % rand_ssrc_id
        sr_packet += 'uint:32=%d' % rand_ntp_timestamp_MSL
        sr_packet += 'uint:32=%d' % rand_ntp_timestamp_LSW
        sr_packet += 'uint:32=%d' % rand_rtp_timestamp
        sr_packet += 'uint:32=%d' % rand_sender_packet_count
        sr_packet += 'uint:32=%d' % rand_sender_octet_count
        send_to_target(sr_packet.tobytes())

def fuzz_RR_packet_advance(count):
    global  TEST_CASE_ID
    # fuzz fraction
    for i in range(256):
        rr_packet = BitArray()
        rtcp_RR_types['length'] = 7
        rr_packet += 'uint:2=%d' % rtcp_RR_types['version']
        rr_packet += 'uint:1=%d' % rtcp_RR_types['padding']
        rr_packet += 'uint:5=%d' % rtcp_RR_types['rc']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['packet_type']
        rr_packet += 'uint:16=%d' % rtcp_RR_types['length']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['ssrc_sender']
        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        print("[*] Test type : Basis RR packet Fraction Lost Test , Payload : %d " %( i ))
        rr_packet += 'uint:8=%d' % i
        # rr_packet += 'uint:8=%d' % rtcp_RR_types['fraction_lost']

        rr_packet += 'uint:24=%d' % rtcp_RR_types['cumulative_packet_loss']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['extended_highest_sequence_number']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['interarrival_jitter']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['lsr']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['dlsr']
        send_to_target(rr_packet.tobytes())

    # fuzz cumulative_packet_loss
    cumulative_packet_loss_max = 2 ** 24 - 1
    for i in range(1000):
        rr_packet = BitArray()
        rtcp_RR_types['length'] = 7
        rr_packet += 'uint:2=%d' % rtcp_RR_types['version']
        rr_packet += 'uint:1=%d' % rtcp_RR_types['padding']
        rr_packet += 'uint:5=%d' % rtcp_RR_types['rc']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['packet_type']
        rr_packet += 'uint:16=%d' % rtcp_RR_types['length']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['ssrc_sender']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['fraction_lost']
        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        rand_cumulative_packet_loss = random.randint(0,cumulative_packet_loss_max)
        print("[*] Test type : Basis RR packet Cumulative_Packet_Loss Test , Payload : %d " %( rand_cumulative_packet_loss))
        rr_packet += 'uint:24=%d' % rand_cumulative_packet_loss
        rr_packet += 'uint:32=%d' % rtcp_RR_types['extended_highest_sequence_number']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['interarrival_jitter']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['lsr']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['dlsr']
        send_to_target(rr_packet.tobytes())



    # fuzz extended_highest_sequence_number
    extended_highest_sequence_number_max = 2 ** 32 - 1
    for i in range(1000):
        rr_packet = BitArray()
        rtcp_RR_types['length'] = 7
        rr_packet += 'uint:2=%d' % rtcp_RR_types['version']
        rr_packet += 'uint:1=%d' % rtcp_RR_types['padding']
        rr_packet += 'uint:5=%d' % rtcp_RR_types['rc']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['packet_type']
        rr_packet += 'uint:16=%d' % rtcp_RR_types['length']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['ssrc_sender']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['fraction_lost']
        rr_packet += 'uint:24=%d' % rtcp_RR_types['cumulative_packet_loss']
        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        rand_extended_highest_sequence_number = random.randint(0,extended_highest_sequence_number_max)
        print("[*] Test type : Basis RR packet Extended_Highest_Sequence_Number Test , Payload : %d " %( rand_extended_highest_sequence_number))
        rr_packet += 'uint:32=%d' % rand_extended_highest_sequence_number

        rr_packet += 'uint:32=%d' % rtcp_RR_types['interarrival_jitter']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['lsr']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['dlsr']
        send_to_target(rr_packet.tobytes())

    # fuzz interarrival_jitter
    interarrival_jitter_max = 2 ** 32 - 1
    for i in range(1000):
        rr_packet = BitArray()
        rtcp_RR_types['length'] = 7
        rr_packet += 'uint:2=%d' % rtcp_RR_types['version']
        rr_packet += 'uint:1=%d' % rtcp_RR_types['padding']
        rr_packet += 'uint:5=%d' % rtcp_RR_types['rc']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['packet_type']
        rr_packet += 'uint:16=%d' % rtcp_RR_types['length']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['ssrc_sender']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['fraction_lost']
        rr_packet += 'uint:24=%d' % rtcp_RR_types['cumulative_packet_loss']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['extended_highest_sequence_number']

        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        rand_interarrival_jitter = random.randint(0,interarrival_jitter_max)
        print("[*] Test type : Basis RR packet Interarrrival_Jitter Test , Payload : %d " %( rand_interarrival_jitter))
        rr_packet += 'uint:32=%d' % rand_interarrival_jitter
        # rr_packet += 'uint:32=%d' % rtcp_RR_types['interarrival_jitter']

        rr_packet += 'uint:32=%d' % rtcp_RR_types['lsr']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['dlsr']
        send_to_target(rr_packet.tobytes())

    # fuzz lsr
    lsr_max = 2 ** 32 - 1
    for i in range(1000):
        rr_packet = BitArray()
        rtcp_RR_types['length'] = 7
        rr_packet += 'uint:2=%d' % rtcp_RR_types['version']
        rr_packet += 'uint:1=%d' % rtcp_RR_types['padding']
        rr_packet += 'uint:5=%d' % rtcp_RR_types['rc']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['packet_type']
        rr_packet += 'uint:16=%d' % rtcp_RR_types['length']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['ssrc_sender']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['fraction_lost']
        rr_packet += 'uint:24=%d' % rtcp_RR_types['cumulative_packet_loss']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['extended_highest_sequence_number']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['interarrival_jitter']

        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        rand_lsr = random.randint(0,lsr_max)
        print("[*] Test type : Basis RR packet LSR Test , Payload : %d " %( rand_lsr))
        rr_packet += 'uint:32=%d' % rand_lsr

        rr_packet += 'uint:32=%d' % rtcp_RR_types['dlsr']
        send_to_target(rr_packet.tobytes())

    # fuzz dslr
    dlsr_max = 2 ** 32 - 1
    for i in range(1000):
        rr_packet = BitArray()
        rtcp_RR_types['length'] = 7
        rr_packet += 'uint:2=%d' % rtcp_RR_types['version']
        rr_packet += 'uint:1=%d' % rtcp_RR_types['padding']
        rr_packet += 'uint:5=%d' % rtcp_RR_types['rc']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['packet_type']
        rr_packet += 'uint:16=%d' % rtcp_RR_types['length']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['ssrc_sender']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['fraction_lost']
        rr_packet += 'uint:24=%d' % rtcp_RR_types['cumulative_packet_loss']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['extended_highest_sequence_number']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['interarrival_jitter']
        rr_packet += 'uint:32=%d' % rtcp_RR_types['lsr']

        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        rand_dslr = random.randint(0,dlsr_max)
        print("[*] Test type : Basis RR packet DSLR Test , Payload : %d " %( rand_dslr))
        rr_packet += 'uint:32=%d' % rand_dslr
        send_to_target(rr_packet.tobytes())

def fuzz_RR_packet_basis(count):
    global  TEST_CASE_ID
    ssrc_id_max = 2**32 - 1
    for i in range(count):
        rr_packet = BitArray()
        rtcp_RR_types['length'] = 1
        rr_packet += 'uint:2=%d' % rtcp_RR_types['version']
        rr_packet += 'uint:1=%d' % rtcp_RR_types['padding']
        rr_packet += 'uint:5=%d' % rtcp_RR_types['rc']
        rr_packet += 'uint:8=%d' % rtcp_RR_types['packet_type']
        rr_packet += 'uint:16=%d' % rtcp_RR_types['length']
        print("[*] Test case ID:%d" %(TEST_CASE_ID) + " START")
        TEST_CASE_ID += 1
        rand_ssrc_id = random.randint(0,ssrc_id_max)
        print("[*] Test type : Basis RR packet SSRC identifier Test , Payload : %d " %(rand_ssrc_id))
        rr_packet += 'uint:32=%d' % rand_ssrc_id
        send_to_target(rr_packet.tobytes())

def start_fuzz():
    rtcp_packet = BitArray()


    # raw_input(TEST_CASE_ID)
    print "[*] Test Function : fuzz_RR_packet_basis Start"
    fuzz_RR_packet_basis(1000)
    print "[*] Test Function : fuzz_RR_packet_basis Finished"

    print "[*] Test Function : fuzz_RR_packet_advance Start"
    fuzz_RR_packet_advance(10)
    print "[*] Test Function : fuzz_RR_packet_advance Finished"

    print "[*] Test Function : fuzz_SR_packet_basis Start"
    fuzz_SR_packet_basis(50000)
    print "[*] Test Function : fuzz_SR_packet_basis Finished"

    print "[*] Test Function : fuzz_RR_packet_advance Start"
    fuzz_SR_SDES_packet_basis(1000)
    print "[*] Test Function : fuzz_RR_packet_advance Finished"

   # rtp_packet += 'uint:16=%d' % rtp_packet_types['sequence_number']
    # rtp_packet += 'uint:32=%d' % rtp_packet_types['timev']
    # rtp_packet += 'uint:32=%d' % rtp_packet_types['ssrc_id']
    # rtp_packet.append('0x41'*80)
    # print(rtp_packet)
    # print(rtp_packet[4:8])
    # raw_input(len(rtp_packet[4:8]))
    # print(rtp_packet)
    # raw_input(len(rtp_packet))
    # for count in range(STOPAFTER):

def computeKey():
    username = 'admin'
    realm = 'RTSP'
    password = 'pass'
    nonce = '0000040dY892418598785d2a2304a74adf22f6098f2792'
    method = 'SETUP'
    url = 'rtsp://192.168.1.56:554/stream0'

    m1 = hashlib.md5(username + ":" + realm + ":" + password).hexdigest()
    m2 = hashlib.md5(method + ":" + url).hexdigest()
    response = hashlib.md5(m1 + ":" + nonce + ":" + m2).hexdigest()
    # raw_input(response)
    return response


if '__main__' == __name__:
    # pcap_reader = RawPcapReader('rtsp_rtp_example.pcap')
    # key = computeKey()
    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
    print "[*]                      WELCOME                   [*]"
    print "[*]                RTCPfuzzer version 1.0          [*]"
    print "[*]                rtcp protocol fuzzer            [*]"
    print "[*]                Author : Leon Zhang             [*]"
    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
    print "[*]              Your Preferences                     "
    print "[*] Target Host :", RHOST, "on PORT", RPORT
    print "[*] Time Delay between two requests :", DELAY, "Sec"
    print "[*] Fuzzing with Metasploit Pattern :", msfpat
    print "[*] Fuzzing case : ",STOPAFTER



    raw_input('Are you ready to start fuzzing test?,(using ctrl+c to terminate)')
    start_fuzz()
    # for index,pkt in enumerate(pcap_reader):
    #     if index > 60:

            # raw_input(index)
            # pkt[0].show()
            # raw_input(hexdump(pkt[0][71]))
            # raw_input(pkt)
