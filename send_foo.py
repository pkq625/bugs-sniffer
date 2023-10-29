from scapy.all import *
import threading
import time
import sys

from scapy.layers.inet import UDP, IP

running = True


class MyProtocol(Packet):
    name = "foo"
    fields_desc = [
        ByteField("type", 0),
        ByteField("flags", 0),
        IntField("sequence_num", 0),
        IPField("ipaddr", "127.0.0.1"),
    ]


class Thread_send(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        n = 0
        foo_packet = MyProtocol()
        while running:
            n += 1
            if random.choice(["src", "dst"]) == 'src':
                udp_packet = IP(dst="192.168.202.129") / UDP(sport=9999, dport=1234) / foo_packet
            else:
                udp_packet = IP(dst="192.168.202.129") / UDP(dport=9999, sport=1234) / foo_packet
            send(udp_packet)


class Thread_stop(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        ver = raw_input("press any key to stop send...")
        global running
        running = False


if __name__ == '__main__':
    t1 = Thread_send()
    t2 = Thread_stop()
    t1.start()
    t2.start()
