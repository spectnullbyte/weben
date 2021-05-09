#!/bin/python3

import argparse
import os
import nmap3

import settings
import webserver

class mainProgram():
    """ Main Class of the program """
    def __init__(self):
        self.get_arguments()
        self.services = {}
        self.settings = settings.Settings()

    def get_arguments(self):
        parse=argparse.ArgumentParser(description='Automatically scan a target IP')
        parse.add_argument('-T', dest='target', help='The target IP address')
        parse.add_argument('-P', dest='port', help='The target port (If not specified, all ports will be scanned)')
        args = parse.parse_args()
        print(f"Selected Target : {args.target}")
        print(f"Selected Port : {args.port}")
        self.target = args.target
        self.port = args.port

    def scan_ports(self):
        nmap = nmap3.Nmap()
        nmapResults = nmap.scan_top_ports(f"{self.target}",args="")
        openPorts = nmapResults.keys()
        listOfAllPorts = nmapResults[self.target]['ports']
        listOfOpenPorts = [port['portid'] for port in listOfAllPorts if port['state'] == 'open']
        numberOfOpenPorts = len(listOfOpenPorts)
        print(f"Total number of open ports : {numberOfOpenPorts}")
        print("List of Open Ports : ")
        for port in listOfOpenPorts:
            print(port)
            
        stringOfOpenPorts = ' '.join(listOfOpenPorts)
        print("[*] Launching Service Detection...")
        for p in nmap.nmap_version_detection(self.target, args=f"-p {stringOfOpenPorts}")[self.target]['ports']:
            currentPort = p['portid']
            currentService = p['service']['name']
            print(f"Port {currentPort} runs the following service : {currentService}")
            if currentService == 'http':
                print(f"[*] Launching Directory Enumeration on port {currentPort}...")
                print("[*] Launching Gobuster...")
                self.webserver = webserver.Webserver(self,currentPort)
                self.webserver.directory_enumeration()
                


if __name__ == "__main__":
    print("\33[0;37;40m") 
    weben = mainProgram()
    weben.scan_ports()
