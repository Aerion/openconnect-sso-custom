# CSD stub, heavily inspired by https://gitlab.com/openconnect/openconnect/-/blob/master/trojans/csd-post.sh

import os
import platform
import socket
import subprocess
from xml.etree import ElementTree
import zlib

import requests
import structlog


logger = structlog.get_logger()


def csd_post(vpn_url: str, ticket: str, stub: str):
    csd_hostname = vpn_url.split("/")[2]
    token = _get_token(csd_hostname, ticket, stub)
    csd_contents = _generate_csd_contents(csd_hostname)
    return _post_csd_contents(csd_hostname, token, csd_contents)


def _get_token(csd_hostname: str, ticket: str, stub: str):
    token_url = (
        f"https://{csd_hostname}/+CSCOE+/sdesktop/token.xml?ticket={ticket}&stub={stub}"
    )
    token_response = requests.get(token_url)
    root = ElementTree.fromstring(token_response.content)
    token = root.find("token").text
    return token


def _generate_csd_contents(csd_hostname: str):
    result = ""
    result += _generate_host_entries()
    result += _generate_port_entries()

    csd_data_url = f"https://{csd_hostname}/CACHE/sdesktop/data.xml"
    csd_data_response = requests.get(csd_data_url)
    csd_data_xml = ElementTree.fromstring(csd_data_response.text)

    hostscan_values = [
        field.get("value") for field in csd_data_xml.findall(".//hostscan/field")
    ]

    for hostscan_value in hostscan_values:
        entry_parts = [part.strip("'") for part in hostscan_value.split(",")]

        entry_type = entry_parts[0]
        entry_name = entry_parts[1]
        entry_value = entry_parts[2]

        if entry_type != hostscan_value:
            if entry_type == "File":
                result += _generate_file_entry(entry_name, entry_value)
            elif entry_type == "Process":
                result += _generate_process_entry(entry_name, entry_value)
            elif entry_type == "Registry":
                pass
            else:
                logger.debug(
                    f"Unhandled hostscan element of type '{entry_type}': '{entry_name}'/'{entry_value}'"
                )
        else:
            logger.debug(f"Unhandled hostscan field '{hostscan_value}'")

    return result


def _generate_file_entry(entry_name: str, entry_value: str):
    basename = os.path.basename(entry_value)
    entry_contents = f"""endpoint.file["{entry_name}"]={{}};
endpoint.file["{entry_name}"].path="{entry_value}";
endpoint.file["{entry_name}"].name="{basename}";
"""
    try:
        ts = int(os.stat(entry_value).st_mtime)
        lastmod = int(platform.time() - ts)
        crc32 = hex(zlib.crc32(open(entry_value, "rb").read()) & 0xFFFFFFFF)
        entry_contents += f"""endpoint.file["{entry_name}"].exists="true";
endpoint.file["{entry_name}"].lastmodified="{lastmod}";
endpoint.file["{entry_name}"].timestamp="{ts}";
endpoint.file["{entry_name}"].crc32="{crc32}";
"""
    except OSError:
        entry_contents += f'endpoint.file["{entry_name}"].exists="false";\n'
    return entry_contents


def _generate_process_entry(entry_name: str, entry_value: str):
    if (
        subprocess.call(
            ["pidof", entry_value], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        == 0
    ):
        exists = "true"
    else:
        exists = "false"
    return f"""endpoint.process["{entry_name}"]={{}};
endpoint.process["{entry_name}"].name="{entry_value}";
endpoint.process["{entry_name}"].exists="{exists}";\n"""


def _generate_host_entries():
    return f"""endpoint.os.version="{platform.system()}";
endpoint.os.servicepack="{platform.release()}";
endpoint.os.architecture="{platform.machine()}";
endpoint.policy.location="Default";
endpoint.device.protection="none";
endpoint.device.protection_version="3.1.03103";
endpoint.device.hostname="{socket.gethostname()}";
endpoint.device.MAC["FFFF.FFFF.FFFF"]="true";
endpoint.device.protection_extension="3.6.4900.2";
endpoint.fw["IPTablesFW"]={{}};
endpoint.fw["IPTablesFW"].exists="true";
endpoint.fw["IPTablesFW"].description="IPTables (Linux)";
endpoint.fw["IPTablesFW"].version="1.6.1";
endpoint.fw["IPTablesFW"].enabled="ok";
"""


def _generate_port_entries() -> str:
    entries = ""
    for port in [9217, 139, 53, 22, 631, 445, 9216]:
        entries += f"""endpoint.device.port["{port}"]="true";
    endpoint.device.tcp4port["{port}"]="true";
    endpoint.device.tcp6port["{port}"]="true";
"""
    return entries


def _post_csd_contents(csd_hostname: str, token: str, csd_contents: str):
    headers = {
        "Expect": "",
        "Cookie": f"sdesktop={token}",
        "Content-Type": "text/xml",
    }
    response = requests.post(
        f"https://{csd_hostname}/+CSCOE+/sdesktop/scan.xml?reusebrowser=1",
        headers=headers,
        data=csd_contents,
    )
    logger.debug("CSD response received", content=response.text)

    root = ElementTree.fromstring(response.text)
    status_element = root.find("status")
    return status_element is not None and status_element.text == "TOKEN_SUCCESS"
