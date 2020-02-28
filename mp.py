#!/usr/bin/env python3

import argparse
import getch
import getpass
import json
import os
import pathlib
import pyperclip as clipboard
import sys
import webbrowser

from pbe_with_md5_and_triple_des import PBEWithMD5AndTripleDES

def get_is_match(string):
    string = string.lower()
    def is_match(dictionary) :
        if string in dictionary['name'].lower() or string in dictionary['path'].lower():
            return True
        return False
    return is_match


def main():
    parser = argparse.ArgumentParser(description='MyPass, a simple password manager')
    parser.add_argument('-p', dest='password', help="Password for encryption, otherwise prompt")
    parser.add_argument('-f', dest='search_for', help="Text to filter on, otherwise list all")
    parser.add_argument('filepath', nargs='?', default=os.path.join(str(pathlib.Path.home() ), '.mp.json'), help="Source file, otherwise ~/.mp.json")
    args = parser.parse_args()

    if not os.path.isfile(args.filepath):
        exit('Error: file not found: ' + args.filepath)

    password = ""
    if args.password is None:
        password = getpass.getpass()
    else:
        password = args.password

    cipher = PBEWithMD5AndTripleDES()
    with open(args.filepath) as json_file:
        secrets = json.load(json_file)
        if args.search_for is not None:
            is_match = get_is_match(args.search_for)
            secrets = list(filter(is_match, secrets))
        
        if len(secrets) > 10:
            for p in secrets:
                print(p['name'] + " " + p['login'] + " " + p['email'] + " " + cipher.decrypt(p['encryptedPassword'], password))
            exit('Too many matches found, ' + str(len(secrets)) + ".  Please narrow you search.")

        i = 0
        for p in secrets:
            print(str(i) + ') ' + p['name'] + '  ' + p['login'] + '  ' + p['email'] + '  ' + p['path'])
            i += 1
        print('x) exit')

        sys.stdout.write('Which one? ')
        sys.stdout.flush()
        c = getch.getch()
        if c.lower() == 'x':
            exit()
        
        secret = secrets[int(c)]
        path = secret['path']
        print('  ' + secret['name'] + ' | ' + secret['login'] + ' | ' + secret['email'] + ' | ' + path)
        if path.lower().startswith('http'):
            webbrowser.open(secret['path'])
        clipboard.copy(cipher.decrypt(secrets[int(c)]['encryptedPassword'], password))        


if __name__ == "__main__":
    main()
