#!/bin/python3

# This is where you can adjust the settings before launching the program.
# It is recommended to go through all the settings to maximize the chance of getting interesting results

class Settings():
    def __init__(self):
        # The path for the wordlist that will be used to enumerate directories
        self.dirEnumWordlist = '/usr/share/wordlists/dirb/common.txt'

        # If you are looking for a particular word, you can add it in this list
        self.keys = ['pass','pwd','p4ss','flag','fl4g','key','hidden']
