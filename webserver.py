#!/bin/python3

import argparse
import os
import nmap3
import requests
import re

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
        while continueFlag and i < 3:
            listOfDirectories[i] = []
            for directory in listOfDirectories[i-1]:
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

        
    def sourcecode_scan(self):
        parsedPages = []
        pagesToParse = self.pages[:]
        while len(pagesToParse) > 0:
            for page in pagesToParse:
                if page not in parsedPages:
                    parsedPages.append(pagesToParse.pop(pagesToParse.index(page)))
                    try:
                        returnedPage = requests.get(f"http://{self.server}:{self.port}{page}")
                    except:
                        print(f"{page} is unreachable. Ignored")
                        continue
                    pattern = '|'.join(self.settings.keys)
                    matches = re.finditer(pattern,returnedPage.text)
                    for match in matches:
                        print(f"The word {match.group(0)} found in \33[1;37;40m{page}\33[0;37;40m : ...{returnedPage.text[match.start()-10:match.start()-1]}\33[1;37;40m{returnedPage.text[match.start():match.end()]}\33[0;37;40m{returnedPage.text[match.end()+1:match.end()+10]}...".replace('\n',''))
                    links = re.findall(r'<a\s+href="(.*?)"', returnedPage.text)
                    for link in links:
                        if 'mailto:' in link:
                            print(f"Mail detected : {link}")
                        elif "http://" not in link and link[0] != "#":
                            currentPath = page[:page.rfind('/')]
                            if link[:2] == '../':
                                pageToAdd = currentPath[:currentPath.rfind('/')]
                                if len(link) > 3:
                                    pageToAdd += link[3:]
                            elif link[0] != '/':
                                pageToAdd = f"{currentPath}/{link}"
                            else:
                                pageToAdd = f"{currentPath}{link}"
                            if pageToAdd not in pagesToParse:
                                print(f"\33[1;37;41m[*] Page Detected : {pageToAdd}\33[0;37;40m")
                                pagesToParse.append(pageToAdd)
        print("[*] Scanning of the source code is complete") 
