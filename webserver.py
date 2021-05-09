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

    def directory_enumeration(self,recursive = False):
        os.system(f"gobuster dir -u {self.server}:{self.port} -w {self.settings.dirEnumWordlist}")
