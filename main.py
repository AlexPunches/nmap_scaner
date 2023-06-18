import argparse
import asyncio
import json

from config import NmapPortStatus as Status
from config import ScanType
from services.nmap_scaner import NmapScaner
from services.nmap_xml_parser import NmapXmlParser

scaner: NmapScaner = NmapScaner()
parser: NmapXmlParser = NmapXmlParser()


async def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument('ips', type=argparse.FileType('r'), help='IP\'s')
    arguments.add_argument('ports', type=argparse.FileType('r'), help='ports')
    args = arguments.parse_args()
    ports_list = [port.strip() for port in args.ports]
    ips_list = [ip.strip() for ip in args.ips]

    tasks = []
    result = {}  # будем копить результаты в памяти
    for ip in ips_list:
        result[ip] = {}
        tasks.append((
            ScanType.top,
            asyncio.create_task(scaner.scan_top_ports(ip=ip))
        ))
        tasks.append((
            ScanType.important,
            asyncio.create_task(scaner.scan_ports(ip=ip, ports=ports_list))
        ))

    for scan_type, task in tasks:
        if scan_type == ScanType.top:
            ip, top_ports_xml = await task
            result[ip]['top_ports_opened'] = parser.parse_ports(top_ports_xml)
        if scan_type == ScanType.important:
            ip, important_ports_xml = await task
            important_ports = parser.parse_ports(important_ports_xml)
            result[ip]['important_ports_closed'] = dict(filter(
                lambda item: item[1] == Status.closed, important_ports.items()
            ))

    # кодга все готово, распечатаем
    print(json.dumps(result, indent=4))


if __name__ == '__main__':
    asyncio.run(main())
