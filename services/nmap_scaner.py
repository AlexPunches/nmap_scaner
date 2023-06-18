import asyncio
import os
import shutil
from asyncio.subprocess import Process

from pydantic import IPvAnyAddress

import exception as exc
from config import config, logger


class NmapScaner:
    def __init__(self):
        self.nmap_cmd = config.nmap_cmd
        self.nmap_exec = shutil.which(self.nmap_cmd)

    async def scan_ports(
              self,
              ip: IPvAnyAddress,
              ports: list,
    ) -> tuple:
        """Сканировать определенные порты хоста.

        По сути -- это метод подготовки параметров для run_scan().
        """
        ports_by_commas = ','.join(str(port).strip() for port in ports)
        params_for_nmap = ['-v', '-oX', '-', f'-p{ports_by_commas}', f'{ip}']
        logger.info(f'Запускаю scan_ports хоста {ip}')
        return ip, await self._run_scan(params=params_for_nmap)

    async def scan_top_ports(
              self,
              ip: IPvAnyAddress,
              top: int = config.top_ports,
    ) -> tuple:
        """"Сканировать top наиболее распространенных портов.

        По сути -- это метод подготовки параметров для run_scan().
        """
        params_for_nmap = [
            '-v', '-sV', '-oX', '-', '--open', '--top-ports', f'{top}', f'{ip}'
        ]
        logger.info(f'Запускаю scan_top_ports хоста {ip}')
        return ip, await self._run_scan(params=params_for_nmap)

    async def _run_scan(self, params: list[str]) -> str:
        """Запустить сканирование.

        По условию задачи, сканер зависит от nmap на машине.
        """
        if not self.nmap_exec or not os.path.exists(self.nmap_exec):
            raise exc.NmapNotInstalledError

        try:
            nmap_process: Process = await asyncio.create_subprocess_exec(
                self.nmap_cmd, *params,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await nmap_process.communicate()
        except Exception as e:
            raise exc.NmapError(e)
        if nmap_process.returncode != 0:
            raise exc.NmapError(stderr)
        logger.info(f'Готов результат для {params[-1]}')
        return stdout.decode()
