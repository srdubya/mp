#!/usr/bin/env python3

import argparse
import datetime
import getch
import getpass
import json
import os
import pathlib
import pyperclip as clipboard
import shutil
import sys
import webbrowser

from pbe_with_md5_and_triple_des import PBEWithMD5AndTripleDES


def get_is_match(string):
    string = string.lower()

    def is_match(dictionary):
        if string in dictionary['name'].lower() or string in dictionary['path'].lower():
            return True
        return False

    return is_match


def matching_indexes(string, secrets):
    for i in range(0, len(secrets)):
        if string in secrets[i]['name'].lower() or string in secrets[i]['path'].lower():
            yield i


def get_edit(secret, param_name, dirty):
    print('Editing field: __' + param_name + '__')
    print('  Current: ' + secret[param_name])
    new_value = input('      New: ').rstrip()
    if len(new_value) > 0:
        print('      Now: ' + new_value)
        return new_value, True
    print('    Still: ' + secret[param_name])
    return secret[param_name], dirty


def get_password_edit(current_value, cipher, password, dirty):
    new_password = getpass.getpass('New Password: ')
    if len(new_password) == 0:
        print('OK, unchanged')
        return current_value, dirty
    again_password = getpass.getpass('Again please: ')
    if new_password != again_password:
        print('MISMATCH, unchanged')
        return current_value, dirty
    print('OK, changed')
    ret = str(cipher.encrypt(new_password, password=password), 'utf-8')
    return ret, True


def save_backup(current_path):
    home_path = str(pathlib.Path.home())
    backup_folder = os.path.join(home_path, '.mp.backup')
    if not os.path.isdir(backup_folder):
        os.mkdir(backup_folder, 0o700)
    now = datetime.datetime.now()
    backup_path = os.path.join(backup_folder, now.strftime("%Y-%m-%dT%H:%M:%S.%f") + '.json')
    shutil.copy2(current_path, backup_path)


def save_secrets(file_path, secrets):
    with open(file_path, 'w') as outfile:
        json.dump(secrets, outfile, indent=2)


def main():
    parser = argparse.ArgumentParser(description='MyPass, a simple password manager', allow_abbrev=True)
    parser.add_argument('-p, --password', dest='password', help="Password for encryption, otherwise prompt")
    parser.add_argument('-f, --find', dest='search_for', help="Text to filter on, otherwise list all")
    parser.add_argument('--edit', action='store_true', help='To edit a secret')
    parser.add_argument('--show', action='store_true', help='To show the secret')
    parser.add_argument('file_path', nargs='?', default=os.path.join(str(pathlib.Path.home()), '.mp.json'),
                        help="Source file, otherwise ~/.mp.json")
    args = parser.parse_args()

    if not os.path.isfile(args.file_path):
        exit('Error: file not found: ' + args.file_path)

    cipher = PBEWithMD5AndTripleDES()
    with open(args.file_path, 'rb') as json_file:
        secrets = json.load(json_file)

    if args.password is None:
        password = getpass.getpass()
    else:
        password = args.password
    try:
        for secret in secrets:
            cipher.decrypt(secret['encryptedPassword'], password)
    except UnicodeDecodeError:
        exit('Sorry, incorrect password')

    target_secrets = []
    if args.search_for is not None:
        target_secrets = list(matching_indexes(args.search_for.lower(), secrets))

    if len(target_secrets) > 10:
        for i in target_secrets:
            print(secrets[i]['name'] + " | " + secrets[i]['login'] + " | " + secrets[i]['email'])
        print()
        exit('Too many matches found, ' + str(len(secrets)) + ".  Please narrow you search.")

    i = 0
    for index in target_secrets:
        print(str(i) + ') ' + secrets[index]['name'] + ' | ' + secrets[index]['login'] + ' | '
              + secrets[index]['email'] + ' | ' + secrets[index]['path'])
        i += 1
    print('x) exit')

    sys.stdout.write('Which one? ')
    sys.stdout.flush()
    c = getch.getch()
    if c.lower() == 'x':
        exit('OK, never mind')

    target_secret = target_secrets[int(c)]
    path = secrets[target_secret]['path']
    print('  ' + secrets[target_secret]['name'] + ' | ' + secrets[target_secret]['login'] + ' | '
          + secrets[target_secret]['email'] + ' | ' + path)

    if args.edit:
        dirty = False
        secrets[target_secret]['name'], dirty = get_edit(secrets[target_secret], 'name', dirty)
        secrets[target_secret]['login'], dirty = get_edit(secrets[target_secret], 'login', dirty)
        secrets[target_secret]['email'], dirty = get_edit(secrets[target_secret], 'email', dirty)
        secrets[target_secret]['encryptedPassword'], dirty = get_password_edit(
            secrets[target_secret]['encryptedPassword'], cipher, password, dirty
        )
        if dirty:
            save_backup(args.file_path)
            save_secrets(args.file_path, secrets)
    elif args.show:
        print(cipher.decrypt(secrets[target_secret]['encryptedPassword'], password))
    else:
        if path.lower().startswith('http'):
            webbrowser.open(path)
        clipboard.copy(cipher.decrypt(secrets[target_secret]['encryptedPassword'], password))


if __name__ == "__main__":
    main()
