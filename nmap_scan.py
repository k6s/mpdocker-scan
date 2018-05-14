#!/usr/bin/env python3

import subprocess
import sys
import MySQLdb

CMD=['nmap', '-sS', '-Pn', '-T4', '-sV', '-O', '--version-all', '--osscan-guess']

def     get_services(host):
    servs = []
    try:
        xx = host.split(b'SERVICE')[1].split(b'\n')[1:]
        for x in xx:
            try:
                port = x.split(b'/')[0]
                fields = [z for z in x.split(b' ') if z.strip()]
                sck = fields[0].split(b'/')[1]
                tp = fields[2]
                version = soft = b''
                if len(fields) > 3:
                    soft = fields[3]
                if len(fields) > 4:
                    version = fields[4]
                servs.append({'port': port, 'sck': sck, 'type': tp, 'version': version})
            except:
                continue
        return (servs)
    except:
        return []

def     get_os(host):
    try:
        return (host.split(b'OS CPE: ')[1].split(b'\n')[0])
    except:
        return ''

def     get_mac(host):
    try:
        mac = host.split(b'MAC Address: ')[1]
        return mac.split(b' ')[0]
    except:
        return ''

def     parse(output):
    res = output.split(b'Nmap scan report for ')[1:]
    hosts = []
    for r in res:
        host = r.split(b'\n')
        ip = host[0]
        services = get_services(r)
        os = get_os(r)
        mac = get_mac(r)
        hosts.append({'ip': ip, 'mac': mac, 'os': os, 'services': services})
    return hosts

def     db_push_entver(db, part, vendor, product, version):
    cur = db.cursor()
    cur.execute(b'SELECT * FROM entity WHERE part=\'' + bytes([part])
            + b'\' AND vendor LIKE \'' + vendor + b'\''
            + b' AND product LIKE \'' + product + b'\'')
    rows = cur.fetchall()
    if len(rows) < 1:
        cur.execute(b'INSERT INTO entity(part, vendor, product) \
                VALUES(\'' + bytes([part]) + b'\', \'' + vendor + b'\', \'' + product  + b'\')')
        db.commit()
        cur.execute(b'SELECT * FROM entity WHERE part LIKE \'' + bytes([part])
            + b'\' AND vendor LIKE \'' + vendor
            + b'\' AND product LIKE \'' + product + b'\'')
        rows = cur.fetchall()
    id_entity = str(rows[0][0]).encode('ascii')
    print(b'SELECT * FROM entity_version WHERE id_entity=' + id_entity
            + b' AND version LIKE \'' + version + b'\'')
    cur.execute(b'SELECT * FROM entity_version WHERE id_entity=' + id_entity
            + b' AND version LIKE \'' + version + b'\'')
    rows = cur.fetchall()
    if len(rows) < 1:
        cur.execute(b'INSERT INTO entity_version(id_entity, version) VALUES('
                + id_entity + b', \'' + version  + b'\')')
        db.commit()
        cur.execute(b'SELECT * FROM entity_version WHERE id_entity=' + id_entity
                + b' AND version = \'' + version + b'\'')
        rows = cur.fetchall()
    id_entity_version = str(rows[0][0]).encode('ascii')
    cur.close()
    return id_entity_version

def     db_push(db, hosts):
    for host in hosts:
        if len(host['mac']) < 8:
            continue
        id_entity_version = b'3'
        if host['os'] != '':
           part = host['os'].split(b':')[1][1]
           vendor = host['os'].split(b':')[2]
           product = host['os'].split(b':')[3]
           version = host['os'].split(b':')[4]
           id_entity_version = db_push_entver(db, part, vendor, product, version)
        cur = db.cursor()
        cur.execute(b'SELECT * FROM device WHERE mac LIKE \'' + host['mac'] + b'\'')
        rows = cur.fetchall()
        if len(rows) > 0:
            cur.execute(b'UPDATE device SET ip=\'' + host['ip']
                    + b'\', id_entity_version=' + id_entity_version
                    + b' WHERE id=' + str(rows[0][0]).encode('ascii'))
        else:
            cur.execute(b'INSERT INTO device(id_entity_version, ip, mac) VALUES('
                    + id_entity_version + b',\''
                    + host['ip'] + b'\',\'' + host['mac'] + b'\')')
        db.commit()
        cur.execute(b'SELECT * FROM device WHERE mac LIKE \'' + host['mac'] + b'\'')
        rows = cur.fetchall()
        id_device = str(rows[0][0]).encode('ascii')
        id_entity_version = str(1).encode('ascii')
        for service in host['services']:
            cur.execute(b'SELECT * FROM service WHERE id_device=' + id_device
                    + b' AND portnum=' + service['port'])
            rows = cur.fetchall()
            if len(rows) < 1:
                cur.execute(b'INSERT INTO service(id_entity_version, id_device, portnum) VALUES('
                        + id_entity_version + b',' + id_device + b',' + service['port'] + b')')
                db.commit()
        cur.close()

def     usage():
    print('usage:', sys.argv[0], 'iprange sqlhost sqluser sqlpw sqldb')
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 6:
        usage()
    target = sys.argv[1]
    # output = subprocess.Popen(CMD + [target], stdout=subprocess.PIPE).communicate()[0]
    output = b'Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-14 21:01 UTC\nNmap scan report for 192.168.1.1\nHost is up (0.021s latency).\nNot shown: 996 closed ports\nPORT     STATE SERVICE    VERSION\n23/tcp   open  telnet?\n53/tcp   open  domain     dnsmasq 2.15-OpenDNS-1\n80/tcp   open  tcpwrapped\n5000/tcp open  tcpwrapped\nMAC Address: C4:04:15:48:5A:48 (Netgear)\nDevice type: general purpose\nRunning: Linux 2.6.X\nOS CPE: cpe:/o:linux:linux_kernel:2.6.22\nOS details: Linux 2.6.22 (embedded, ARM)\nNetwork Distance: 1 hop\n\nNmap scan report for 192.168.1.24\nHost is up (0.094s latency).\nAll 1000 scanned ports on 192.168.1.24 are closed\nMAC Address: 4C:4E:03:76:C4:19 (TCT mobile)\nToo many fingerprints match this host to give specific OS details\nNetwork Distance: 1 hop\n\nNmap scan report for 192.168.1.26\nHost is up (0.032s latency).\nAll 1000 scanned ports on 192.168.1.26 are closed\nMAC Address: 38:E6:0A:81:D4:44 (Unknown)\nToo many fingerprints match this host to give specific OS details\nNetwork Distance: 1 hop\n\nNmap scan report for 192.168.1.23\nHost is up (0.000069s latency).\nAll 1000 scanned ports on 192.168.1.23 are closed\nToo many fingerprints match this host to give specific OS details\nNetwork Distance: 0 hops\n\nOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .\nNmap done: 256 IP addresses (4 hosts up) scanned in 527.26 seconds\n'
    hosts = parse(output)
    db = MySQLdb.connect(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    print('\n\n', output)
    db_push(db, hosts)
    db.close()
    sys.exit(0)
