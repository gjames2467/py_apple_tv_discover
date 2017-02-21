import errno
import select

from dnslib.dns import DNSRecord
from six import int2byte

from device_search.methods.params import _MAX_MSG_TYPICAL, _MAX_MSG_ABSOLUTE, _FLAGS_QR_MASK, _FLAGS_QR_QUERY, _FLAGS_QR_RESPONSE, _MDNS_ADDR, _MDNS_PORT, _MAX_MSG_ABSOLUTE, _CLASS_UNIQUE, _TYPE_ANY, _TYPE_TXT, _FLAGS_QR_QUERY, _TYPE_A, _TYPE_NS, _TYPE_MD, _TYPE_MF, _TYPE_CNAME, _TYPE_SOA, _TYPE_MB, _TYPE_MG, _TYPE_MR, _TYPE_NULL, _TYPE_WKS, _TYPE_PTR, _TYPE_HINFO, _TYPE_MINFO, _TYPE_MX, _TYPE_TXT, _TYPE_AAAA, _TYPE_SRV, _TYPE_ANY, _CLASS_IN, _CLASS_CS, _CLASS_CH, _CLASS_HS, _CLASS_NONE, _CLASS_ANY, _CLASS_MASK, _CLASS_UNIQUE, _CLASSES, _TYPES


def new_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        reuseport = socket.SO_REUSEPORT
    except AttributeError:
        pass
    else:
        try:
            s.setsockopt(socket.SOL_SOCKET, reuseport, 1)
        except (OSError, socket.error) as err:
            # OSError on python 3, socket.error on python 2
            if not err.errno == errno.ENOPROTOOPT:
                raise

    # OpenBSD needs the ttl and loop values for the IP_MULTICAST_TTL and
    # IP_MULTICAST_LOOP socket options as an unsigned char.
    ttl = struct.pack(b'B', 255)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    loop = struct.pack(b'B', 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)

    s.bind(('', _MDNS_PORT))
    return s
import netifaces
import enum

@enum.unique
class InterfaceChoice(enum.Enum):
    Default = 1
    All = 2

def get_all_addresses(address_family):
    HOST_ONLY_NETWORK_MASK = '255.255.255.255'
    tmp_interface_list = []
    for x in netifaces.interfaces():
        try:
            tmp_interface = netifaces.ifaddresses(x).get(2)[0].get('addr')
            if tmp_interface==HOST_ONLY_NETWORK_MASK:
                continue
            if tmp_interface != None:
                tmp_interface_list.append(tmp_interface)
        except:
            pass

    return list(set(tmp_interface_list))
def normalize_interface_choice(choice, address_family):
    if choice is InterfaceChoice.Default:
        choice = ['0.0.0.0']
    elif choice is InterfaceChoice.All:
        choice = get_all_addresses(address_family)
    return choice


class DNSOutgoing(object):

    """Object representation of an outgoing packet"""

    def __init__(self, flags, multicast=True):
        self.finished = False
        self.id = 0
        self.multicast = multicast
        self.flags = flags
        self.names = {}
        self.data = []
        self.size = 12

        self.questions = []
        self.answers = []
        self.authorities = []
        self.additionals = []

    def add_question(self, record):
        """Adds a question"""
        self.questions.append(record)

    def add_answer(self, inp, record):
        """Adds an answer"""
        if not record.suppressed_by(inp):
            self.add_answer_at_time(record, 0)

    def add_answer_at_time(self, record, now):
        """Adds an answer if if does not expire by a certain time"""
        if record is not None:
            if now == 0 or not record.is_expired(now):
                self.answers.append((record, now))

    def add_authorative_answer(self, record):
        """Adds an authoritative answer"""
        self.authorities.append(record)

    def add_additional_answer(self, record):
        """Adds an additional answer"""
        self.additionals.append(record)

    def pack(self, format_, value):
        self.data.append(struct.pack(format_, value))
        self.size += struct.calcsize(format_)

    def write_byte(self, value):
        """Writes a single byte to the packet"""
        self.pack(b'!c', int2byte(value))

    def insert_short(self, index, value):
        """Inserts an unsigned short in a certain position in the packet"""
        self.data.insert(index, struct.pack(b'!H', value))
        self.size += 2

    def write_short(self, value):
        """Writes an unsigned short to the packet"""
        self.pack(b'!H', value)

    def write_int(self, value):
        """Writes an unsigned integer to the packet"""
        self.pack(b'!I', int(value))

    def write_string(self, value):
        """Writes a string to the packet"""
        assert isinstance(value, bytes)
        self.data.append(value)
        self.size += len(value)

    def write_utf(self, s):
        """Writes a UTF-8 string of a given length to the packet"""
        utfstr = s.encode('utf-8')
        length = len(utfstr)
        if length > 64:
            raise NamePartTooLongException
        self.write_byte(length)
        self.write_string(utfstr)

    def write_character_string(self, value):
        assert isinstance(value, bytes)
        length = len(value)
        if length > 256:
            raise NamePartTooLongException
        self.write_byte(length)
        self.write_string(value)

    def write_name(self, name):
        """Writes a domain name to the packet"""

        if name in self.names:
            # Find existing instance of this name in packet
            #
            index = self.names[name]

            # An index was found, so write a pointer to it
            #
            self.write_byte((index >> 8) | 0xC0)
            self.write_byte(index & 0xFF)
        else:
            # No record of this name already, so write it
            # out as normal, recording the location of the name
            # for future pointers to it.
            #
            self.names[name] = self.size
            parts = name.split('.')
            if parts[-1] == '':
                parts = parts[:-1]
            for part in parts:
                self.write_utf(part)
            self.write_byte(0)

    def write_question(self, question):
        """Writes a question to the packet"""
        self.write_name(question.name)
        self.write_short(question.type)
        self.write_short(question.class_)

    def write_record(self, record, now):
        """Writes a record (answer, authoritative answer, additional) to
        the packet"""
        self.write_name(record.name)
        self.write_short(record.type)
        if record.unique and self.multicast:
            self.write_short(record.class_ | _CLASS_UNIQUE)
        else:
            self.write_short(record.class_)
        if now == 0:
            self.write_int(record.ttl)
        else:
            self.write_int(record.get_remaining_ttl(now))
        index = len(self.data)
        # Adjust size for the short we will write before this record
        #
        self.size += 2
        record.write(self)
        self.size -= 2

        length = len(b''.join(self.data[index:]))
        self.insert_short(index, length)  # Here is the short we adjusted for

    def packet(self):
        """Returns a string containing the packet's bytes

        No further parts should be added to the packet once this
        is done."""
        if not self.finished:
            self.finished = True
            for question in self.questions:
                # print('questo9n')
                # print(question)
                self.write_question(question)
            for answer, time_ in self.answers:
                self.write_record(answer, time_)
            for authority in self.authorities:
                self.write_record(authority, 0)
            for additional in self.additionals:
                self.write_record(additional, 0)

            self.insert_short(0, len(self.additionals))
            self.insert_short(0, len(self.authorities))
            self.insert_short(0, len(self.answers))
            self.insert_short(0, len(self.questions))
            self.insert_short(0, self.flags)
            if self.multicast:
                self.insert_short(0, 0)
            else:
                self.insert_short(0, self.id)
            # self.data

        return b''.join(self.data)
class DNSEntry(object):

    """A DNS entry"""

    def __init__(self, name, type_, class_):
        self.key = name.lower()
        self.name = name
        self.type = type_
        self.class_ = class_ & _CLASS_MASK
        self.unique = (class_ & _CLASS_UNIQUE) != 0

    def __eq__(self, other):
        """Equality test on name, type, and class"""
        return (isinstance(other, DNSEntry) and
                self.name == other.name and
                self.type == other.type and
                self.class_ == other.class_)

    def __ne__(self, other):
        """Non-equality test"""
        return not self.__eq__(other)

    @staticmethod
    def get_class_(class_):
        """Class accessor"""
        return _CLASSES.get(class_, "?(%s)" % class_)

    @staticmethod
    def get_type(t):
        """Type accessor"""
        return _TYPES.get(t, "?(%s)" % t)

    def to_string(self, hdr, other):
        """String representation with additional information"""
        result = "%s[%s,%s" % (hdr, self.get_type(self.type),
                               self.get_class_(self.class_))
        if self.unique:
            result += "-unique,"
        else:
            result += ","
        result += self.name
        if other is not None:
            result += ",%s]" % other
        else:
            result += "]"
        return result


class DNSQuestion(DNSEntry):

    """A DNS question entry"""

    def __init__(self, name, type_, class_):
        DNSEntry.__init__(self, name, type_, class_)

    def answered_by(self, rec):
        """Returns true if the question is answered by the record"""
        return (self.class_ == rec.class_ and
                (self.type == rec.type or self.type == _TYPE_ANY) and
                self.name == rec.name)

    def __repr__(self):
        """String representation"""
        return DNSEntry.to_string(self, "question", None)


import socket
import struct


def decode_labels(message, offset):
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF), offset

        if (length & 0xC0) != 0x00:
            raise StandardError("unknown label encoding")

        offset += 1

        if length == 0:
            return labels, offset

        labels.append(*struct.unpack_from("!%ds" % length, message, offset))
        offset += length


DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")

def decode_question_section(message, offset, qdcount):
    questions = []

    for _ in range(qdcount):
        qname, offset = decode_labels(message, offset)

        qtype, qclass = DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
        offset += DNS_QUERY_SECTION_FORMAT.size

        question = {"domain_name": qname,
                    "query_type": qtype,
                    "query_class": qclass}

        questions.append(question)

    return questions, offset


DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")

def decode_dns_message(message):

    id, misc, qdcount, ancount, nscount, arcount = DNS_QUERY_MESSAGE_HEADER.unpack_from(message)

    qr = (misc & 0x8000) != 0
    opcode = (misc & 0x7800) >> 11
    aa = (misc & 0x0400) != 0
    tc = (misc & 0x200) != 0
    rd = (misc & 0x100) != 0
    ra = (misc & 0x80) != 0
    z = (misc & 0x70) >> 4
    rcode = misc & 0xF

    offset = DNS_QUERY_MESSAGE_HEADER.size
    questions, offset = decode_question_section(message, offset, qdcount)

    result = {"id": id,
              "is_response": qr,
              "opcode": opcode,
              "is_authoritative": aa,
              "is_truncated": tc,
              "recursion_desired": rd,
              "recursion_available": ra,
              "reserved": z,
              "response_code": rcode,
              "question_count": qdcount,
              "answer_count": ancount,
              "authority_count": nscount,
              "additional_count": arcount,
              "questions": questions}

    return result
def create_socket_request(name,_TYPE_SRV_AND_CLASS_IN=[(33, 1), (16, 1), (1, 1)]):
    """

    :param name: name of tcp service
    :param list of tuples with service type and class
    :return: the out object which contains packets you need to send through all interfaces
    """
    out = DNSOutgoing(_FLAGS_QR_QUERY)
    for itm in _TYPE_SRV_AND_CLASS_IN:
        _TYPE_SRV=itm[0]
        _CLASS_IN=itm[1]
        out.add_question(
            DNSQuestion(name, _TYPE_SRV, _CLASS_IN))

        out.add_question(
            DNSQuestion(name, _TYPE_TXT, _CLASS_IN))
    return out
def create_broadcast_sockets(_listen_socket):
    _send_scokets=[]
    for i in normalize_interface_choice(InterfaceChoice.All,2):
        # print(i)
        try:

            _listen_socket.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton(_MDNS_ADDR) + socket.inet_aton(i))

            respond_socket = new_socket()
            respond_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(i))

            _send_scokets.append(respond_socket)
        except:
            continue

    return _send_scokets
def get_login_info(name,_TYPE_SRV_AND_CLASS_IN=[(33, 1), (16, 1), (1, 1)]):
    timeout = .5
    socs=[]
    out = create_socket_request(name,_TYPE_SRV_AND_CLASS_IN=[(33, 1), (16, 1), (1, 1)])

    _listen_socket = new_socket()

    for _broadcast_scoket in create_broadcast_sockets(_listen_socket):
        _broadcast_scoket.sendto(out.packet(),0,(_MDNS_ADDR, _MDNS_PORT))
    info_dict={}

    tmp_output_dns_data=True
    while tmp_output_dns_data==True:
        rr, wr, er = select.select([_listen_socket], [], [], timeout)

        for _socket in rr:
            data,addr= _socket.recvfrom(_MAX_MSG_ABSOLUTE)
            tmp_data=data

            if 'apple' in str(tmp_data) and 'aV' in str(tmp_data):
                # return DNSRecord.parse(data)
                tmp_output_dns_data=DNSRecord.parse(data)
                break
    info_dict['ip']=addr[0]
    info_dict['port']=tmp_output_dns_data.rr[1].rdata._port

    for x in tmp_output_dns_data.rr[0].rdata.data:
        k,v=x.decode('utf-8').split('=')
        info_dict[k]=v

    info_dict['device_tcp_name']=name
    info_dict['HSGID']=info_dict['hG']
    info_dict['ADDRESS']=info_dict['ip']
    info_dict['NAME']=info_dict['Name']
    return info_dict
