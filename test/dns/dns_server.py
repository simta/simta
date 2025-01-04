#!/usr/bin/env python3

import json
import logging
import socket
import struct
import sys

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.zone

from argparse import ArgumentParser
from pathlib import Path
from select import select
from threading import Thread


logger = logging.getLogger(__name__)
zones = {}


class DNSQuery:
    def __init__(self, data, tcp=False):
        self.data = data
        self.tcp = tcp

        if self.tcp:
            data_len = struct.unpack('!H', data[:2])
            self.data = data[2:2 + data_len[0]]

        try:
            self.message = dns.message.from_wire(self.data)
        except dns.exception.DNSException as e:
            logger.error(f'Failed to parse query: {e}')
            self.message = None
            return

        self.qname = self.message.question[0].name
        self.qtype = self.message.question[0].rdtype
        self.qclass = self.message.question[0].rdclass

        logger.info(
            (
                f'{dns.opcode.to_text(self.message.opcode())}: '
                f'{self.qname} '
                f'{dns.rdataclass.to_text(self.qclass)} '
                f'{dns.rdatatype.to_text(self.qtype)} '
                f'data_len={len(self.data)} '
            )
        )

        self.response = dns.message.make_response(self.message)

        self.cnames = set()
        self.edns_flags = 0
        self.edns_options = []

        if self.message.opcode() != dns.opcode.QUERY:
            self.response.set_rcode(dns.rcode.NOTIMP)
            return

        if self.message.edns == -1:
            self.response.use_edns(edns=False)
        elif self.message.edns > 0:
            self.response.set_rcode(dns.rcode.BADVERS)
            return

        if self.response.rcode() == dns.rcode.FORMERR:
            return

        if self.qclass != dns.rdataclass.IN:
            self.response.set_rcode(dns.rcode.REFUSED)
            return

        if 127 < self.qtype < 256:
            self.response.set_rcode(dns.rcode.NOTIMP)
            return

        self.response.set_rcode(dns.rcode.NOERROR)
        self.response.flags |= dns.flags.AA

        self.lookup(self.qname, self.qtype)

        if self.message.edns != -1:
            self.response.use_edns(edns=0, ednsflags=self.edns_flags, options=self.edns_options)

    @property
    def response_data(self):
        max_size = 1232
        if self.tcp:
            max_size = 65533
        elif self.message.edns == -1:
            max_size = 512

        try:
            wire = self.response.to_wire(max_size=max_size)
        except dns.exception.TooBig:
            self.response.flags |= dns.flags.TC
            self.response.answer = []
            self.response.authority = []
            self.response.additional = []
            wire = self.respose.to_wire()
        if self.tcp:
            msglen = struct.pack('!H', len(wire))
            wire = msglen + wire
        return wire

    def add_rrset(self, zone, section, rrset):
        if rrset in section:
            return
        section.append(rrset)

    def add_soa(self, zone):
        soa_rrset = zone.get_rrset(zone.origin, dns.rdatatype.SOA)
        self.add_rrset(zone, self.response.authority, soa_rrset)

    def set_nxdomain(self, zone, sname):
        self.response.set_rcode(dns.rcode.NXDOMAIN)
        self.add_soa(zone)

    def find_rrtype(self, zone, sname, stype, wildcard=None):
        rrname = self.qname if wildcard else sname

        if stype != dns.rdatatype.CNAME:
            rds = zone.get_rdataset(sname, dns.rdatatype.CNAME)
            if rds:
                self.lookup_cname(zone, rrname, sname, stype, rds)
                return

        rds = zone.get_rdataset(sname, stype)
        if rds:
            rrset = dns.rrset.RRset(rrname, dns.rdataclass.IN, stype)
            rrset.update(rds)
            self.add_rrset(zone, self.response.answer, rrset)
            return

        # no data, just add the SOA
        self.add_soa(zone)

    def lookup_cname(self, zone, rrname, sname, stype, cname_rds):
        if sname in self.cnames:
            logger.warning(f'CNAME loop: {sname}')
            self.response.set_rcode(dns.rcode.SERVFAIL)
            return
        self.cnames.add(sname)
        rrset = dns.rrset.RRset(rrname, dns.rdataclass.IN, dns.rdatatype.CNAME)
        rrset.update(cname_rds)
        self.add_rrset(zone, self.response.answer, rrset)
        self.lookup(cname_rds[0].target, stype)

    def lookup_name(self, zone, qname, sname, stype):
        node = zone.get_node(sname)
        if node is None:
            wildcard_name = dns.name.Name((b'*',) + sname.labels[1:])
            if zone.get_node(wildcard_name):
                self.find_rrtype(zone, wildcard_name, stype, wildcard=sname)
                return True
            self.set_nxdomain(zone, sname)
            return True

        if sname == qname:
            self.find_rrtype(zone, sname, stype)
            return True

        return False

    def lookup(self, qname, qtype):
        zone = None
        for zone_name in zones.keys():
            if qname.is_subdomain(zone_name):
                zone = zones[zone_name]
                break

        if zone is None:
            if not self.response.answer:
                self.response.set_rcode(dns.rcode.REFUSED)
                if self.message.edns != -1:
                    self.edns_options.append(dns.edns.EDEOption(dns.edns.EDECode.NOT_AUTHORITATIVE, 'Not authoritative for zone'))
            return

        current_name = zone.origin
        label_list = list(qname.relativize(current_name).labels)
        while True:
            if self.lookup_name(zone, qname, current_name, qtype):
                return
            if not label_list:
                return
            label = label_list.pop()
            current_name = dns.name.Name((label, *current_name.labels))


def create_ents(zone):
    seen = set([zone.origin])
    for node in list(zone.keys()):
        while node not in seen:
            seen.add(node)
            zone.find_node(node, create=True)
            node = node.parent()


def load_zone(name, fname):
    logger.info(f'Loading {name} from {fname}...')
    zone_name = dns.name.from_text(name)
    try:
        zone = dns.zone.from_file(str(fname), origin=zone_name, relativize=False)
    except dns.exception.DNSException as e:
        logger.critical(f'Failed to load {name}: {e}')
        sys.exit(1)

    create_ents(zone)
    zones[zone_name] = zone


def create_zones(data):
    logger.info('Creating zones from data...')

    for (rname, values) in data.items():
        zone_name = dns.name.from_text('.'.join(rname.split('.')[-2:]))
        if zone_name not in zones:
            zone = dns.zone.Zone(zone_name, relativize=False)
            rds = zone.find_rdataset(zone.origin, dns.rdatatype.SOA, create=True)
            rds.add(
                dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.SOA,
                    'localhost.test. simta.test. (1 300 300 6000 30)',
                ),
            )
            zones[zone_name] = zone
        zone = zones[zone_name]
        rname = dns.name.from_text(rname)

        for v in values:
            if v == 'TIMEOUT':
                # FIXME: implement
                continue

            for (rtype, content) in v.items():
                if rtype == 'MX':
                    content = f'{content[0]} {content[1]}.'
                elif rtype == 'TXT':
                    content = f'"{content}"'

                rds = zone.find_rdataset(rname, rtype, create=True)
                rds.add(dns.rdata.from_text(dns.rdataclass.IN, rtype, content, relativize=False))

    for zone in zones.values():
        create_ents(zone)


def handle_connection(sock, tcp=False, buf_size=2048):
    if tcp:
        sock, conninfo = sock.accept()
        data = sock.recv(buf_size)
    else:
        data, conninfo = sock.recvfrom(buf_size)

    addr, port = conninfo[0:2]
    logger.info(f'CONN: {addr}:{port} tcp={tcp} raw_len={len(data)}')

    query = DNSQuery(data, tcp)

    if not query.message or not query.response:
        return

    logger.info(f'RESPONSE: {dns.rcode.to_text(query.response.rcode())} raw_len={len(query.response_data)}')

    message = query.response_data
    if tcp:
        sent = 0
        try:
            while sent < len(message):
                progress = sock.send(message[sent:])
                if progress == 0:
                    logger.error('socket connection broken')
                    raise RuntimeError('socket connection broken')
                sent += progress
        except OSError as e:
            logger.error(f'sock.send() raised {e}')
            return
        sock.close()
    else:
        sock.sendto(message, (addr, port))


def main():
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(logging.StreamHandler(sys.stderr))

    logger.info('Initializing...')

    parser = ArgumentParser()
    parser.add_argument('--port', default=10053, type=int)
    parser.add_argument('--zone-data')
    args = parser.parse_args()

    if args.zone_data:
        create_zones(json.loads(args.zone_data))
    else:
        base_path = Path(__file__).parent
        for zone_file in base_path.glob('*.zone'):
            load_zone(zone_file.stem, zone_file)

    sockets = {}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', args.port))
        sockets[sock] = {
            'tcp': False,
        }

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', args.port))
        sock.listen()
        sockets[sock] = {
            'tcp': True,
        }

    except OSError as e:
        logger.critical(f'Failed to listen on {args.port}: {e}')
        sys.exit(1)

    logger.info(f'Listening on {args.port}')

    while True:
        try:
            ready = select(sockets.keys(), [], [])
        except OSError as e:
            logger.critical(f'select() raised {e}')
            sys.exit(1)

        if not ready[0]:
            continue

        for sock in ready[0]:
            Thread(target=handle_connection, args=(sock, sockets[sock]['tcp'])).start()


if __name__ == '__main__':
    main()
