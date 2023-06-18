import xml.etree.ElementTree as ET

from config import logger


class NmapXmlParser:
    """Класс, в котором парсим вернувшийся ответ от nmap."""

    @staticmethod
    def parse_ports(xml_str):
        """"Распарсить XML.

        Получить информацию про сканированные порты.
        Максимально хардкодный, НЕуниверсальный, примитивныый парсер,
        подходит только для конкретного задания.
        По условию большего вроде бы не нужно.
        """
        ports = {}
        root = ET.fromstring(xml_str)
        # у нас всегда один хост
        host = root.find('host')
        if not host:
            logger.warn('Host not found')
            return None
        for port in host.findall('ports/port'):
            port_id = port.get('portid')
            port_status = port.find('state').get('state')
            if port_id and port_status:
                ports[port_id] = port_status
        return ports
