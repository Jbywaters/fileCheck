import getopt
import socket
import sys

import dpkt


def pcapParse(file):
    returning = []
    retString = []
    queries = 0
    servfails = 0
    with open(file, 'rb') as F:
        pcap = dpkt.pcap.Reader(F)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except:
                continue
            if eth.type != 2048:
                continue
            try:
                ip = eth.data
            except:
                continue
            if ip.p != 17:
                continue
            try:
                udp = ip.data
            except:
                continue
            if udp.sport != 53 and udp.dport != 53:
                continue
            try:
                dns = dpkt.dns.DNS(udp.data)
            except:
                continue
            if dns.qr != dpkt.dns.DNS_R:
                continue
            if dns.opcode != dpkt.dns.DNS_QUERY:
                continue
            if len(dns.an) < 1:
                retString.append(dns.qd[0].name + '\n[RESPONSE] - Server Error')
                queries+=1
                servfails+=1
                continue
            for qname in dns.an:
                retString.append(qname.name + '\n[RESPONSE] - ' + socket.inet_ntoa(qname.ip))
                queries+=1
    returning.append(retString)
    returning.append(queries)
    returning.append(servfails)
    return returning
def usage():
    print "[!] Provide a file name"
def badfile():
    print "[!] Bad File Name, Cannot open"

def main(argv):
    file_name = ""
    try:
        opts, args = getopt.getopt(argv, 'f:')
    except getopt.GetoptError:
        print usage
        sys.exit(2)

    if len(opts) == 0:
        usage()
        sys.exit()

    for opt, arg in opts:
        if opt == "-f":
            file_name = arg
        else:
            usage()
            sys.exit()
    try:
        open(file_name, 'rb')
    except IOError:
        badfile()
        sys.exit()
    print "Parsing PCAP for DNS Requests:\n"
    pcapparsed = pcapParse(file_name)
    for parsedLine in pcapparsed[0]:
        print parsedLine
    print '\n'+str(pcapparsed[1])+': Queries\n'+str(pcapparsed[2])+': Server Failures'
if __name__ == '__main__':
    main(sys.argv[1:])