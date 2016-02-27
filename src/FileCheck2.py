import sys, os, sys, getopt, urllib, urllib2, re, EnglishDetect, av_multiscan
from operator import itemgetter
import dpkt
import time
import avsubmit
import pescanner
import pefile
try:
    import simplejson
except ImportError:
    print 'You must install simplejson for VirusTotal, see http://www.undefined.org/python/'
try:
    import hashlib
except ImportError:
    print 'You must install hashlib to check MD5/SHA256 hashes'

# VirusTotal API Key
api = 'C:\Git\Confidential\APIKEYS.txt'
f = open(api, "rb") #one line file with just the api Key
vtapi = f.read()
f.close()



class VirusTotal:

    def __init__(self, file):
        self.alerts = ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'ReadProcessMemory',
          'CreateProcess', 'WinExec', 'ShellExecute', 'HttpSendRequest', 'InternetReadFile', 'InternetConnect',
          'CreateService', 'StartService']
        self.file = file
        f = open(self.file, "rb")
        self.content = f.read()
        f.close()
        self.strings = ""
        charFreq = open("LFrequency.txt")
        self.lowerLetters = [i.strip().split() for i in charFreq.readlines()]
        charFreq.close()

    def check(self, res):
        url = "https://www.virustotal.com/api/get_file_report.json"
        parameters = {"resource": res,
                      "key": vtapi}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()
        response_dict = simplejson.loads(json)
        try:
            return response_dict.get("report")[1]
        except:
            return {}

    def upload_file(self):
        host = "www.virustotal.com"
        selector = "http://www.virustotal.com/api/scan_file.json"
        fields = [("key", vtapi)]
        file_to_send = self.content
        files = [("file", os.path.basename(self.file), file_to_send)]
        return avsubmit.post_multipart(host, selector, fields, files)

    def submit(self):
        resource = hashlib.md5(self.content).hexdigest()
        detects = self.check(resource)
        if len(detects) > 0:
            print 'File already exists on VirusTotal!'
            return detects
        print 'File does not exist on VirusTotal, uploading...'
        json = self.upload_file()
        if json.find("scan_id") != -1:
            offset = json.find("scan_id") + len("scan_id") + 4
            scan_id = json[offset:]
            scan_id = scan_id[:scan_id.find("\"")]
            print 'Trying scan_id %s for %d seconds' % (scan_id, avsubmit.MAXWAIT)
            i = 0
            while i < (avsubmit.MAXWAIT / 10):
                detects = self.check(scan_id)
                if len(detects) > 0:
                    return detects
                time.sleep(avsubmit.MAXWAIT / 10)
                i += 1
        return {}

    def process(self):
        chars = r"A-Za-z0-9 "
        shortest_run = 4
        regexp = '[%s]{%d,}' % (chars, shortest_run)
        pattern = re.compile(regexp)
        self.strings = pattern.findall(self.content)
        self.stringscore=[[]]
        self.stringscore[0] = (self.strings)

    def getIPs(self):
        ipregexp = '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ipPattern = re.compile(ipregexp)
        self.ips = ipPattern.findall(self.content)

    def charFrequencyScore(self):
        global newstringnum
        # print len(self.strings
        englishScorer = EnglishDetect.EnglishDetect()
        self.stringscore.append([0]*len(self.stringscore[0]))
        for index, string in enumerate(self.stringscore[0]):
            self.stringscore[1][index] = englishScorer.scoreCheck(string)
        sortedstrings = zip(self.stringscore[0], self.stringscore[1])
        sortedstrings = sorted(sortedstrings, key=lambda score: score[1])
        index=0
        for score in sortedstrings:
            if score[1]<3:
                sortedstrings.pop(index)
            else:
                index+=1
        return sortedstrings

    def check_imports(self, pe):
        ret = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return ret
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                if (imp.name != None) and (imp.name != "") and '\t\t'+imp.name not in ret:
                    warning=0
                    for alert in self.alerts:
                        if imp.name.startswith(alert):
                            ret.append("WARNING\t"+hex(imp.thunk_rva)+'\t'+imp.name)
                            warning = 1
                    if warning==0:
                        ret.append('\t\t'+imp.name)
        return ret
    def check_exports(self, pe):
        ret = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            ret.append('No Exports Found')
            return ret
        for lib in pe.DIRECTORY_ENTRY_EXPORT:
            for exp in lib.exports:
                if (exp.name != None) and (exp.name != ""):
                    ret.append('\t\t'+exp.name)
        return ret

def usage():
    print "[!] Provide a file name"


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

    print "[*] Beginning analysis on " + file_name + "..."
    MD5 = hashlib.md5(open(file_name, 'rb').read()).hexdigest()
    SHA = hashlib.sha256(open(file_name, 'rb').read()).hexdigest()
    ssDeep = av_multiscan.ssdeep(file_name)
    print "MD5 Hash:\t" + MD5
    print "SHA256 Hash:\t" + SHA
    print "SSDEEP:\t" + ssDeep
    vT = VirusTotal(file_name)
    #print vT.submit()
    vT.process()
    i = vT.charFrequencyScore()
    print 'printed strings to strings.txt'
    ipList = vT.getIPs()
    if ipList is None:
        print 'No IPs Detected'
    else:
        print 'IP LIST:\n'
        print ipList
    pe = pefile.PE(file_name)
    print "Magic Number:\t" + hex(pe.DOS_HEADER.e_magic)
    print "Entry Point:\t" + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    print "Sections:"
    print "\tName\tVirtual Address"
    for section in pe.sections:
        print '\t' + section.Name + '\t'+ hex(section.VirtualAddress)
    imports = vT.check_imports(pe)
    print 'Imports: '
    for line in imports:
        print line
    exports = vT.check_exports(pe)
    for line in exports:
        print line
    with open('CryptoLocker.pcap') as F:
        pcap = dpkt.pcap.Reader(F)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except:
                continue
            if eth.type!=2048:
                continue
            try:
                ip=eth.data
            except:
                continue
            if ip.p!=17:
                continue
            try:
                udp=ip.data
            except:
                continue
            if udp.sport!=53 and udp.dport!=53:
                continue
            try:
                dns = dpkt.dns.DNS(udp.data)
            except:
                continue
            if dns.qr != dpkt.dns.DNS_R:
                continue
            if dns.opcode!= dpkt.DNS_QUERY:
                continue
            if len(dns.an)<1:
                continue
            for qname in dns.qd:
                print qname.name




if __name__ == '__main__':
    main(sys.argv[1:])
