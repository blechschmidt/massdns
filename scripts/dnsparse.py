#!/usr/bin/python

import struct
import dns.message
import ipaddress

class UnknownEndianness(Exception):
    pass

class InvalidFileFormat(Exception):
    pass

class UnsupportedFile(Exception):
    pass

class UnexpectedFileEnd(Exception):
    pass

class InvalidValue(Exception):
    pass

class DnsResult:
    def __init__(self, timestamp, resolver, raw):
        self.timestamp = timestamp
        self.resolver = resolver
        self.raw = raw
        self.message = dns.message.from_wire(raw)

class BinaryDnsResultParser:
    def __init__(self, filename, throw_incomplete=False):
        f = open(filename, "rb")
        
        if f.read(8) != b"massdns\0":
            raise InvalidFileFormat("Expected magic bytes")
        
        endianness = f.read(4)
        if endianness == b"\x12\x34\x56\x78":
            endianness = ">"
        elif endianness == b"\x78\x56\x34\x12":
            endianness = "<"
        else:
            raise UnknownEndianness()

        (version,) = struct.unpack(endianness + "I", f.read(4))
        
        (size_len,) = struct.unpack("B", f.read(1))
        size_modifier = self.__size_len_to_modifier__(size_len)

        (time_size, sockaddr_storage_size, family_offset, family_size, port_size,)\
            = struct.unpack(endianness + 5 * size_modifier, f.read(5 * size_len))
        
        time_modifier = self.__size_len_to_modifier__(time_size)
        family_modifier = self.__size_len_to_modifier__(family_size)
        port_modifier = self.__size_len_to_modifier__(port_size)
        
        family_inet = f.read(family_size)
        (sin_addr_offset,) = struct.unpack(endianness + size_modifier, f.read(size_len))
        (sin_port_offset,) = struct.unpack(endianness + size_modifier, f.read(size_len))
        
        family_inet6 = f.read(family_size)
        (sin6_addr_offset,) = struct.unpack(endianness + size_modifier, f.read(size_len))
        (sin6_port_offset,) = struct.unpack(endianness + size_modifier, f.read(size_len))

        self._file = f
        self._throw_incomplete = throw_incomplete
        self._endianness = endianness
        self._time_size = time_size
        self._time_modifier = time_modifier
        self._sockaddr_storage_size = sockaddr_storage_size
        self._family_offset = family_offset
        self._family_size = family_size
        self._port_size = port_size
        self._port_modifier = port_modifier
        self._family_modifier = family_modifier
        self._family_inet = family_inet
        self._family_inet6 = family_inet6
        self._sin_addr_offset = sin_addr_offset
        self._sin6_addr_offset = sin6_addr_offset
        self._sin_port_offset = sin_port_offset
        self._sin6_port_offset = sin6_port_offset

    def results(self):
        msg_header_len = self._time_size + self._sockaddr_storage_size + 2
        while True:
            msg_header = self._file.read(msg_header_len)
            
            if len(msg_header) == 0:
                break
            
            if len(msg_header) < msg_header_len and self._throw_incomplete:
                raise UnexpectedFileEnd()
            
            raw_time = msg_header[0 : self._time_size]
            (timestamp,) = struct.unpack(self._endianness + self._time_modifier, raw_time)
            family_start = self._time_size + self._family_offset
            family = msg_header[family_start:family_start + self._family_size]

            if family == self._family_inet:
                addr_start = self._time_size + self._sin_addr_offset
                raw_ip = msg_header[addr_start : addr_start + 4]
                port_start = self._time_size + self._sin_port_offset
            elif family == self._family_inet6:
                addr_start = self._time_size + self._sin6_addr_offset
                raw_ip = msg_header[addr_start : addr_start + 16]
                port_start = self._time_size + self._sin6_port_offset
            else:
                raise InvalidValue("Unknown IP family")
            raw_port = msg_header[port_start : port_start + self._port_size]
            (port,) = struct.unpack("!" + self._port_modifier, raw_port)

            ip = ipaddress.ip_address(raw_ip)

            (dns_data_len,) = struct.unpack(self._endianness + "H", msg_header[-2:])
            dns_data = self._file.read(dns_data_len)

            if len(dns_data) < dns_data_len and self._throw_incomplete:
                raise UnexpectedFileEnd()

            yield DnsResult(timestamp, (ip, port), dns_data)

    @staticmethod
    def __size_len_to_modifier__(size):
        if size == 1:
            return "B"
        if size == 2:
            return "H"
        if size == 4:
            return "I"
        if size == 8:
            return "Q"
        raise UnsupportedFile()

    def close(self):
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self._file.close()



if __name__ == "__main__":
    import time
    import sys

    if len(sys.argv) < 2:
        print("Expecting a file name containing binary output from MassDNS as parameter")
        sys.exit(1)

    with BinaryDnsResultParser(sys.argv[1], True) as parser:
        for result in parser.results():
            formatted_time = time.strftime("%d %b %Y %H:%M:%S %Z", time.localtime(result.timestamp))
            print(str(result.resolver[0]) + ":" + str(result.resolver[1]) +", " + formatted_time)
            print(str(result.message))
            print("\n")
