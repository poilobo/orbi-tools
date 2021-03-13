from typing import Dict, List
from telnetlib import Telnet
import re
import json
import getpass

from collections import namedtuple

LogEntry = namedtuple(
    "LogEntry", ["message", "source", "mac", "port", "timestamp", "raw"]
)


class OrbiRouter:
    @property
    def re_attack_pattern(self):
        return re.compile(
            r"\[(.*Attack.*)\] from source[\:| ]* ([\d]+\.[\d]+\.[\d]+\.[\d ]+), port ([0-9]+),*( [M|T|W|T|F|S].*$)"
        )

    @property
    def re_dhcp_pattern(self):
        return re.compile(
            r"\[DHCP IP\: ([0-9.]+)*\] to MAC address ([\d\:a-f]+).*( [M|T|W|T|F|S].*$)"
        )

    @property
    def host(self):
        return self._host

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return "password set" if self._password else "password not set"

    @property
    def memory(self):
        return self._read_meminfo()

    def __init__(self, host: str, username: str, password: str) -> None:
        self._host = host
        self._username = username.encode("ascii")
        self._password = password.encode("ascii")

    def _log_splitter(self, log_line: str) -> LogEntry:
        """Returns a parsed log entry row as type LogEntry

        Parses a log entry and returns to formatted result
        """
        logEntry = None

        match = self.re_attack_pattern.search(log_line)

        if match:
            return LogEntry(
                message=match.group(1),
                source=match.group(2),
                mac=None,
                port=match.group(3),
                timestamp=match.group(4),
                raw=log_line,
            )

        match = self.re_dhcp_pattern.search(log_line)

        if match:
            return LogEntry(
                message=match.group(1),
                source=None,
                mac=match.group(2),
                port=None,
                timestamp=match.group(3),
                raw=log_line,
            )

        return LogEntry(
            message=None, source=None, port=None, mac=None, timestamp=None, raw=log_line
        )

    def _read_file_over_telnet(self, path: str) -> List:

        with Telnet(self._host) as tn:
            # tn.interact()
            tn.read_until(b"telnet account:")
            tn.write(self._username + b"\n")

            tn.read_until(b"telnet password:")
            tn.write(self._password + b"\n")

            tn.read_until(b"/#")

            cmd = f"cat {path}\n"
            tn.write(cmd.encode("ascii"))
            tn.read_until(b"\n")

            file_contents = tn.read_until(b"/#").decode("ascii")

            root_pos = (len(file_contents) - file_contents[:-1].find("root@")) * -1

            file_contents = file_contents[:root_pos]

            tn.write(b"exit\n")

            return file_contents

    def read_logs(self) -> List[LogEntry]:

        raw_entries = []

        raw_entries = self._read_file_over_telnet("/var/log/messages")

        # Only keep entries that start with a timestamp
        filtered_entries = [
            entry for entry in raw_entries.split("\r\n") if entry.startswith("[")
        ]

        parsed_entries = []

        for line_num, entry in enumerate(filtered_entries):
            parsed_entries.append(self._log_splitter(entry))

        return parsed_entries

    def satellite_device_info(self) -> Dict:
        raw_json = self._read_file_over_telnet("/home/satellite_device_info")
        satellites = json.loads(raw_json)

        return satellites

    def online_devices(self) -> Dict:
        raw_json = self._read_file_over_telnet("/home/netscan/attach_online_device")
        onlineDevices = json.loads(raw_json)

        return onlineDevices

    def offline_devices(self) -> Dict:
        raw_json = self._read_file_over_telnet("/home/netscan/attach_offline_device")
        offlineDevices = json.loads(raw_json)

        return offlineDevices

    def _read_meminfo(self):
        raw_file = self._read_file_over_telnet("/proc/meminfo")

        meminfo = {}

        for line in raw_file.split("\r\n"):
            line = str(line)
            if (
                line.startswith("MemTotal")
                | line.startswith("MemFree")
                | line.startswith("MemAvailable")
            ):
                key = line.split(":")[0]
                value = line.split(":")[1].strip()
                meminfo[key] = value

        return meminfo


if __name__ == "__main__":
    """
    If telnet access is disable go to: http://<ip_address_of_router>/apply.cgi?/debug_detail.htm
    """
    HOST = "10.50.1.1"

    username = input("Enter Orbi user name: ")
    password = getpass.getpass("Enter Orbi Password: ")

    orbi_router = OrbiRouter(HOST, username, password)

    # entries = orbi_router.read_logs()
    # for entry in [entry for entry in parsedEntries if entry.raw.find("port")]:
    #     print(entry)

    # meminfo = orbi_router.memory
    # satellite_info = orbi_router.satellite_device_info()

    online_devices = orbi_router.online_devices()
    offline_devices = orbi_router.offline_devices()

    for i, device in enumerate(online_devices):
        f'{i}) {device["DeviceName"]}\t\t{device["DeviceIP"]}\t\t{device["DeviceMAC"]}'

    for i, device in enumerate(offline_devices):
        print(
            f'{i}) {device["DeviceName"]}\t\t{device["DeviceIP"]}\t\t{device["DeviceMAC"]} OFFLINE'
        )
