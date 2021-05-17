#!/bin/python3

import argparse
import os
import nmap3
import requests
import re
import random
import string
import threading
import time
import sys

import settings

class Webserver():
    """ The Class for web server scanning """

    def __init__(self,mainParam,port):
        self.port = port # The port that is running the web server
        self.server = mainParam.target # The object that contain general info about the target
        self.settings = mainParam.settings # This stores the global settings to be used by the Webserver class
        self.pages = [] # This list stores all the pages that are detected on the web server
        self.existingItems = [] # This stores existing directories (and files) at each level
        self.scan_status = [] # This stores the status of the progress when scanning a wordlist
        # The below loop initializes the progress status for all threads
        for i in range(self.settings.threads):
            self.scan_status.append(0)
    
    def _scan_wordlist(self, listOfItems, thread, path="",):
        self.existingItems = []
        i = 0
        totalItems = len(listOfItems)
        progress = i * 100 / totalItems
        for item in listOfItems:
            if i % self.settings.threads != thread:
                i += 1
                continue
            else:
                item = str(item.strip("\n"))
                if len(item) == 0:
                    continue
                item = '/'+item.lstrip('/')
                retour = requests.get(f"http://{self.server}:{self.port}{path}{item}")
                if str(retour.status_code) != '404':
                    self.existingItems.append(f"{path}{item}")
                self.scan_status[thread] = i * 100 / totalItems
                i += 1
        
    def _report_status(self):
        average = sum(self.scan_status) / len(self.scan_status)
        status = round(average,0)
        while int(status) != 100:
            time.sleep(1)
            sys.stdout.write(f"\r{status}%")
            sys.stdout.flush()
            average = sum(self.scan_status) / len(self.scan_status)
            status = round(average,0)
        sys.stdout.write(f"\r{status}%\n")
        for i in self.scan_status:
            i = 0

    def directory_enumeration(self):
        continueFlag = True
        currentPathList = []
        listOfDirectories = {}
        listOfDirectories[0] = [""]
        i = 1
        while continueFlag and i < 3:
            listOfDirectories[i] = []
            for directory in listOfDirectories[i-1]:
                if directory == '':
                    currentPath = ""
                else:
                    currentPath = '/'+directory.strip('/')
                print(f"[*] Scanning directories at level {i}")
                print(f"[*] Scanning : {self.server}:{self.port}{currentPath}")
                threads = []
                with open(self.settings.dirEnumWordlist,"r") as wordlist:
                    listOfItems = wordlist.readlines()
                for index in range(self.settings.threads):
                    thread = threading.Thread(target=self._scan_wordlist, args=(listOfItems,index,currentPath))
                    thread.start()
                    threads.append(thread)
                progressThread = threading.Thread(target=self._report_status, args=())
                progressThread.start()
                for thread in threads:
                    thread.join()
                progressThread.join()
                with open(f"tmp.txt","w") as temp:
                    for item in self.existingItems:
                        temp.write(item + '\n')
                with open(f"tmp.txt","r") as enumResults:
                    for result in enumResults.readlines():
                        detectedElement = result.strip('\n')
                        if ("." in detectedElement):
                            print(f"\33[1;37;41m[+] Detected file : {detectedElement}\33[0;37;40m")
                            file_extensions = ['htm','php','txt','js']
                            if any(ext in detectedElement for ext in file_extensions):
                                self.pages.append(currentPath+detectedElement)
                        else:
                            print(f"\33[1;37;41m[+] Detected directory : {detectedElement}\33[0;37;40m")
                            listOfDirectories[i].append(detectedElement)
            continueFlag = listOfDirectories[i]
            i += 1 

        print("Directory and File Enumeration Completed")

        
    def sourcecode_scan(self):
        parsedPages = []
        pagesToParse = self.pages[:]
        pagesToParse.append('/'+''.join([random.choice(string.ascii_letters) for a in range(8)]))
        while len(pagesToParse) > 0:
            for page in pagesToParse:
                if page not in parsedPages:
                    parsedPages.append(pagesToParse.pop(pagesToParse.index(page)))
                    try:
                        returnedPage = requests.get(f"http://{self.server}:{self.port}{page}")
                    except:
                        print(f"http://{self.server}:{self.port}{page} is unreachable. Ignored")
                        continue
                    pattern = '|'.join(self.settings.keys)
                    matches = re.finditer(pattern.lower(),returnedPage.text.lower())
                    for match in matches:
                        print(f"The word {match.group(0)} found in \33[1;37;40m{page}\33[0;37;40m : ...{returnedPage.text[match.start()-10:match.start()]}\33[1;37;40m{returnedPage.text[match.start():match.end()]}\33[0;37;40m{returnedPage.text[match.end():match.end()+10]}...".replace('\n',''))
                    interesting = re.search(r'([a-z0-9]{32})', returnedPage.text)
                    if interesting:
                        print("[*] This seems interesting :")
                        print(f"[+] The word {interesting.group(0)} found in \33[1;37;40m{page}\33[0;37;40m")
                    links = re.findall(r'<a\s+href="(.*?)"', returnedPage.text)
                    for link in links:
                        if len(link) > 0:
                            if 'mailto:' in link:
                                print(f"Mail detected : {link}")
                            elif "http://" not in link and "https://" not in link and link[0] != "#":
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
