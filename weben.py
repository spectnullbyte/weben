#!/bin/python3

import argparse
import os
import nmap3

import settings
import webserver
import ftpserver

class mainProgram():
    """ Main Class of the program """
    def __init__(self):
        self.get_arguments()
        self.services = {}
        self.settings = settings.Settings()
        self.display_banner()

    def get_arguments(self):
        parse=argparse.ArgumentParser(description=self.display_banner())
        parse.add_argument('-T', dest='target', help='The target IP address')
        parse.add_argument('-P', dest='port', help='The target port (If not specified, all ports will be scanned)')
        args = parse.parse_args()
        print(f"Selected Target : {args.target}")
        print(f"Selected Port : {args.port}")
        self.target = args.target
        self.port = args.port

    def scan_ports(self):
        nmap = nmap3.NmapScanTechniques()
        nmapResults = nmap.nmap_tcp_scan(f"{self.target}",args="")
        openPorts = nmapResults.keys()
        listOfAllPorts = nmapResults[self.target]['ports']
        listOfOpenPorts = [port['portid'] for port in listOfAllPorts if port['state'] == 'open']
        numberOfOpenPorts = len(listOfOpenPorts)
        print(f"Total number of open ports : {numberOfOpenPorts}")
        print("List of Open Ports : ")
        for port in listOfOpenPorts:
            print(f"Port {port}")
            
        stringOfOpenPorts = ','.join(listOfOpenPorts)
        print("[*] Launching Service Detection...")
        nmap = nmap3.Nmap()
        versionScan = nmap.nmap_version_detection(self.target, args=f"-p {stringOfOpenPorts}") 
        webservers = []
        ftpservers = []
        for p in versionScan[self.target]['ports']:
            currentPort = p['portid']
            print(f"[*] Port {currentPort} runs the following service : ")
            for key, value in p['service'].items():
                print(f"--{key.title()} : {value}")    
            currentService = p['service']['name']
            if currentService == 'http':
                webservers.append(currentPort)
            elif currentService == 'ftp':
                ftpservers.append(currentPort)

        # If an FTP service exists on the target machine, enumerate it.
        for ftps in ftpservers:
            print(f"[*] Launching FTP enumeration on port {ftps}...")
            self.ftpserver = ftpserver.Ftpserver(self,ftps)
            self.ftpserver.enumeration()

        # If a web server is running  on the target machine, enumerate it.
        for webs in webservers:
            print(f"[*] Launching Directory Enumeration on port {webs}...")
            self.webserver = webserver.Webserver(self,webs)
            self.webserver.directory_enumeration()
            print("[*] Scanning the source code...")
            self.webserver.sourcecode_scan()
    def display_banner(self):
        text_banner = '''
        
888       888        888             888b    888
888   o   888        888             8888b   888
888  d8b  888        888             88888b  888
888 d888b 888 .d88b. 88888b.  .d88b. 888Y88b 888
888d88888b888d8P  Y8b888 "88bd8P  Y8b888 Y88b888
88888P Y8888888888888888  88888888888888  Y88888
8888P   Y8888Y8b.    888 d88PY8b.    888   Y8888
888P     Y888 "Y8888 88888P"  "Y8888 888    Y888

      Automatically scan a target IP

WebeN v1.0
Coded by Spect
Nullbyte team
        
        '''
        print(text_banner)


if __name__ == "__main__":
    print("\33[0;37;40m") 
    weben = mainProgram()
    weben.scan_ports()

