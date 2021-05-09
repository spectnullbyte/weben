#!/bin/python3

import argparse
import os
import nmap3

import settings

class Webserver():
    """ The Class for web server scanning """

    def __init__(self,mainParam,port):
        self.port = port
        self.server = mainParam.target
        self.settings = mainParam.settings
        self.pages = []

    def directory_enumeration(self):
        continueFlag = True
        currentPathList = []
        listOfDirectories = {}
        listOfDirectories[0] = [""]
        i = 1
        while continueFlag:
            listOfDirectories[i] = []
            for directory in listOfDirectories[i-1]:
              #  try:
             #       currentPathList[i-1] = directory
             #   except IndexError:
             #       currentPathList.append("")
             #       currentPathList[i-1] = directory

             #   currentPath = ''.join(currentPathList)
                currentPath = directory
                print(f"[*] Scanning directories at level {i}")
                print(f"[*] Scanning : {self.server}:{self.port}{currentPath}")
                os.system(f"gobuster dir -u http://{self.server}:{self.port}{currentPath} -w {self.settings.dirEnumWordlist} -q --output tmp.txt > /dev/null")
                with open("tmp.txt","r") as enumResults:
                    for result in enumResults.readlines():
                        detectedElement = result.split(" ")[0]
                        if ("." in detectedElement):
                            print(f"\33[1;37;41m[+] Detected file : {currentPath}{detectedElement}\33[0;37;40m")
                            file_extensions = ['htm','php','txt','js']
                            if any(ext in detectedElement for ext in file_extensions):
                                self.pages.append(currentPath+detectedElement)
                        else:
                            print(f"\33[1;37;41m[+] Detected directory : {currentPath}{detectedElement}\33[0;37;40m")
                            listOfDirectories[i].append(currentPath+detectedElement)
            continueFlag = listOfDirectories[i]
            i += 1 

        print("Directory and File Enumeration Completed")

        
