#!/usr/bin/env python3
#
# Copyright (c) 2018 LogMeIn, Inc.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy 
# of this software and associated documentation files (the "Software"), to deal 
# in the Software without restriction, including without limitation the rights 
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
# copies of the Software, and to permit persons to whom the Software is 
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all 
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
# SOFTWARE. 

"""Access Linux hosts using LogMeIn."""

import sys
import io
import re
import os
import logging as log
import logging.handlers
import http.client
import urllib.request
import socket, ssl, pprint
import threading
import time
import select
from multiprocessing import Queue
import multiprocessing
from socket import gethostname
from argparse import ArgumentParser
from hashlib import md5, sha256
from base64 import b64encode, b64decode
from urllib.request import Request, urlopen
import urllib.parse
from contextlib import suppress
from Crypto.Cipher import AES


class Config(object):
    """ Internal configuraion for the app """    
    def __init__(self):
        # LogMeIn Central hostname that might be overwritten from the license file
        self.homeSite = os.getenv("HOMESITE", "secure.logmein.com")

        # Default loglevel (set to log.DEBUG for debugging)
        self.loglevel = os.getenv("LOGLEVEL", "INFO")

        # License file path
        self.globalLicenseFile = os.getenv("LICENSE_FILE", "/var/lib/logmein-host/license.dat")

        # Default port of the web terminal
        self.termPort = os.getenv("TERM_PORT", 23821)

        # Default port of the remote control
        self.rcPort = os.getenv("RC_PORT", 23822)

        # Misc
        self.hostName = gethostname()
        self.versionNum = 12345
        self.prevHostID = 1025570359
        self.idleTimeout = 10
        self.retryTimeout = 30
        self.globalHostIdFile = "/data/{0}.hostid".format(gethostname())
        self.authCode = ""
        self.licenseID = ""
        self.osType = 0x1000004
        self.osSpec = 987168778

        self.verifyConfig()

    def homeSiteTld(self) -> str:
        """ Top-level domain for the homesite (not handling properly the special cases like .co.uk) """
        return ".".join(self.homeSite.split(".")[-2:])

    def versionStr(self) -> str:
        """ (long) version number in str """
        return "4.1.{}".format(self.versionNum)

    def description(self) -> str:
        """ Host description """
        return "{} - Linux".format(self.hostName)

    def uniqueHostId(self) -> str:
        """ Unique host id """
        return md5(self.hostName.encode()).hexdigest()

    def compoundHostID(self) -> str:
        """ Compound host id """
        return self.licenseID + "/" + self.hostName

    def welcomePage(self, raSid : str) -> bytes: 
        """ First page that will be served by logmein-host, all other request will be forwarded """
        pageContent = (
            "<!DOCTYPE html>\r\n" +
            "<html>\r\n" +
            "<head>\r\n" +
            "<meta http-equiv=\"refresh\" content=\"0; URL=/term/\">\r\n" +
            "</head>\r\n" +
            "</html>\r\n"
        )
        customFile = os.path.join(os.path.dirname(__file__), "static", "index.html")
        with suppress(Exception):
            with open(customFile, "r") as f:
                pageContent = f.read()
         
        return (
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/html\r\n" +
            "Set-Cookie: RASID=" + raSid + "; expires=Wed, 21-Mar-2030 17:01:54 GMT; path=/; domain=" + self.homeSiteTld() +"\r\n" +
            "\r\n" +
            pageContent
        ).encode()

    def lastBootTime(self) -> str:
        """ Last boot time (to be implemented....)
            TODO: only on Linux:
           /proc/uptime's first column -> uptime
           (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=uptime)).strftime("%Y-%m-%d %H:%M:%S")
        """
        return "2018-01-01 00:00:00"

    def verifyConfig(self):
        if not self.homeSite.endswith("logmein.com") \
                and not self.homeSite.endswith("3amlabs.net"):
            print("The homesite must be under the \"logmein.com\" or \"3amlabs.net\" domain. " \
                    "Current configuration: HOMESITE={}".format(self.homeSite))
            print("Exiting...")
            sys.exit(1)

    def parseLicenseFile(self, licenseFromStdin):
        config = ""
        cipher = AESCipher("4364b44b3aba62d8fa54b13398d7804d3fe53ea440e1cec280754b915ab573d447545a255abe0181")
        if licenseFromStdin:
            config = cipher.decrypt(sys.stdin.read())
        else:
            try:
                with open("license.dat", "r") as f:
                    config = cipher.decrypt(f.read())
                    log.debug("local config: %s" % config)
            except FileNotFoundError:
                try:
                    with open(self.globalLicenseFile, "r") as f:
                        config = cipher.decrypt(f.read())
                        log.debug("global config: %s" % config)
                except FileNotFoundError:
                    print("License file not found! Please register first.")
                    sys.exit(1)

        for line in config.splitlines():
            if line.startswith("AUTHCODE:"):
                self.authCode = line[9:9+64]
            elif line.startswith("LICENSEID:"):
                self.licenseID = line[10:10+19]
            elif line.startswith("HOMESITE:"):
                # Overwriting config value!
                self.homeSite = line[9:]

    def getLoglevel(self) -> int:
        """ Maps the loglevel names to loglevels """
        nameToLevel = {
            "CRITICAL": log.CRITICAL,
            "FATAL": log.FATAL,
            "ERROR": log.ERROR,
            "WARN": log.WARNING,
            "WARNING": log.WARNING,
            "INFO": log.INFO,
            "DEBUG": log.DEBUG,
            "NOTSET": log.NOTSET,
        }
        return nameToLevel.get(self.loglevel, log.INFO)


class AESCipher(object):
    def __init__(self, key): 
        self.bs = 32
        self.key = sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class Host(object):
    """Connecting host to LogMeIn"""
    def __init__(self, config):
        self.config = config
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.control_ssl = ssl.wrap_socket(self.sock)
        self.control_lock = threading.Lock()
        self.gateway = ""

    def __del__(self):
        self.control_ssl.close()

    def setGatewayName(self):
        query = "/myrahost/list.aspx?weighed=1&os=linux&buildnumber=%d" % self.config.versionNum
        conn = http.client.HTTPSConnection(self.config.homeSite, 443)

        log.info("Getting gateway list from {}".format(self.config.homeSite))
        headers = {"Content-type": "application/x-www-form-urlencoded",
                "Accept": "text/plain"}
        conn.request("GET", query, None, headers)
        r1 = conn.getresponse()
        
        if r1.status != 200:
            log.error("Could not get the gateway list: %d %s" % (r1.status, r1.reason))
            sys.exit(1)

        # OK weight_1 host_1 ... 
        gatewayList = [y for y in (x.strip() for x in r1.read().split()) if y] 
        if len(gatewayList) < 3 or gatewayList[0] != b"OK":
            raise ValueError("Unknown gateway list response: %s" % r1.read())

        self.gateway = gatewayList[2].decode()
        log.info("Gateway: {}".format(self.gateway))

    def connect(self):
        REQ_MSG_AUTH = (
            "RAHOST CTRL {0}\n" +       # license id + "/" + host name
            "LOGON\n" +                 # command
            "-AUTH:{1}\n" +             # host auth code
            "-HOST:{2}\n" +             # license id + "/" + host name
            "-DESC:{3}\n" +             # description
            "-PREVHOSTID:{4}\n" +       # numeric host id
            "-VER:{5}\n" +              # full version string
            "-COMPUTERID:{6}\n" +       # generated HW (and SW?) dependent unique host id
            "-LASTBOOT:{7}\n" +         # last boot time
            "-OSLMI:{8}\n" +            # LMI os type (DWORD)
            "-OSSPEC:{9}\n" +           # LMI os spec (DWORD)
            "-DONE\n"
        )
        REQ_MSG_SUPPORT = (
            "TIMEOUT {0}\n" +
            "DBCMD\n"
        )
        ACK_MSG_OK = "OK"
        log.info("Connecting to gateway")

        self.control_ssl.connect((self.gateway, 443))

        message = REQ_MSG_AUTH.format(self.config.compoundHostID(), 
            self.config.authCode, 
            self.config.hostName, 
            self.config.description(), 
            self.config.prevHostID, 
            self.config.versionStr(), 
            self.config.uniqueHostId(), 
            self.config.lastBootTime(), 
            self.config.osType, 
            self.config.osSpec)
        log.debug("Sending %s" % message)
        with self.control_lock:
            self.control_ssl.write(message.encode())

        data = self.control_ssl.read()
        log.debug("Response: %s" % data)

        buf = io.StringIO(data.decode())
        buf.readline() # OK
        hostIdLine = buf.readline()
        self.hostId = hostIdLine.rstrip()[7:]

        if not data.decode().startswith(ACK_MSG_OK):
            log.error("Authentication failed")
            sys.exit(1)
        
        with self.control_lock:
            self.control_ssl.write(REQ_MSG_SUPPORT.format(self.config.idleTimeout).encode())

    def saveHostId(self):
        if os.path.isdir("/vagrant") and os.path.isdir(os.path.dirname(self.config.globalHostIdFile)):
            with suppress(Exception):
                with open(self.config.globalHostIdFile, "w") as f:
                    f.write("{}\n".format(self.hostId))

    def __keepAlive(self):
        REQ_MSG_PING = "PING\n"

        currThread = threading.currentThread()
        while getattr(currThread, "do_run", True):
            log.debug("Keeping connection alive")
            try:
                with self.control_lock:
                    self.control_ssl.write(REQ_MSG_PING.encode())
            except socket.error as e:
                if e.errno == socket.errno.EPIPE:
                    log.info("Detecting remote disconnect")
                elif e.errno != socket.errno.ECONNRESET and e.errno != socket.errno.ECONNREFUSED:
                    raise
                log.info("Exiting keepAlive")
                return
            except ValueError as e:
                log.debug(e.args)
                return
            time.sleep(self.config.idleTimeout - 2)
        return

    def __exchangeData(self, clientSocket, targetHostSocket):
        if not hasattr(socket, 'SO_KEEPALIVE'):
            raise ValueError("SO_KEEPALIVE is not supported.")
        
        clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        if getattr(socket, 'TCP_KEEPIDLE', None) is not None:
            clientSocket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
        elif getattr(socket, 'TCP_KEEPALIVE', None) and sys.platform == 'darwin':
            clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 0x10)
        clientSocket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)  

        clientSocket.setblocking(0)
        targetHostSocket.setblocking(0)
        
        clientData = b""
        targetHostData = b""
        terminate = False
        while not terminate:
            inputs = [clientSocket, targetHostSocket]
            outputs = []
            
            if len(clientData) > 0:
                outputs.append(clientSocket)
                
            if len(targetHostData) > 0:
                outputs.append(targetHostSocket)
            
            try:
                inputsReady, outputsReady, _ = select.select(inputs, outputs, [], 1.0)
            except Exception as e:
                log.error("exchangeData A {}".format(e))
                break
                
            for inp in inputsReady:
                if inp == clientSocket:
                    try:
                        data = clientSocket.recv(4096)
                        if data != None:
                            if len(data) > 0:
                                targetHostData += data
                                log.debug("Read {} bytes data from CLIENT".format(len(data)))
                            else:
                                terminate = True
                    except Exception as e:
                        log.debug("exchangeData B {}".format(e))
                        break
                elif inp == targetHostSocket:
                    try:
                        data = targetHostSocket.recv(8192)
                        if data != None:
                            if len(data) > 0:
                                clientData += data
                                log.debug("Read {} bytes data from HOST".format(len(data)))
                            else:
                                terminate = True
                    except Exception as e:
                        log.debug("exchangeData C {}".format(e))
                        break
                                            
            for out in outputsReady:
                if out == clientSocket and len(clientData) > 0:
                    try:
                        bytesWritten = clientSocket.send(clientData)
                        log.debug("Sent {} bytes data to CLIENT".format(bytesWritten))
                        if bytesWritten > 0:
                            clientData = clientData[bytesWritten:]
                    except ssl.SSLWantWriteError:
                        pass
                elif out == targetHostSocket and len(targetHostData) > 0:
                    bytesWritten = targetHostSocket.send(targetHostData)
                    log.debug("Sent {} bytes data to HOST".format(bytesWritten))
                    if bytesWritten > 0:
                        targetHostData = targetHostData[bytesWritten:]
        
        clientSocket.close()
        targetHostSocket.close()

    def __createResponse(self, request, client_ssl):
        fwdSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        fwdSock.connect(("127.0.0.1", int(self.config.rcPort)))

        # forwarding request
        fwdSock.sendall(request)

        # exchanging requests/responses until the connection is closed
        self.__exchangeData(client_ssl, fwdSock)

    def __handleDataSock(self, data):
        REQ_MSG_DATASOCK = (
            "RAHOST DATASOCK\n"
            "-HID:{0}\n"
            "-AUTH:{1}\n"
            "-CID:{2}\n"
            "-SSLFWD\n"
            "-DONE\n"
        )

        hostAuth = data[12:12+63].decode()
        buf = io.StringIO(data.decode())
        buf.readline()
        buf.readline() # clientAddr
        connectionId = buf.readline().rstrip()

        message = REQ_MSG_DATASOCK.format(self.hostId, hostAuth, connectionId)
        log.debug("Sending %s" % message)

        # create new connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_ssl = ssl.wrap_socket(sock)
        client_ssl.connect((self.gateway, 443))

        # send datasock request
        client_ssl.send(message.encode())

        while 1:
            chunks = []
            bytes_recv = 1024
            while bytes_recv == 1024:
                try:
                    chunk = client_ssl.recv(1024)
                except socket.error as e:
                    if e.errno != socket.errno.ECONNRESET and e.errno != socket.errno.ECONNREFUSED:
                        raise
                    break
                if chunk == b"":
                    break
                chunks.append(chunk)
                bytes_recv = len(chunk)
            request = b"".join(chunks)
            if request == b"":
                client_ssl.close()
                return

            log.debug("Request: %s[...]" % request[:65])

            decoded = request.decode()
            firstPart = urllib.parse.unquote(decoded[:30])
            if firstPart.startswith("GET / HTTP") or firstPart.startswith("GET /default.html"):
                previousRaSid = re.findall('^Cookie:.*RASID=([A-Za-z0-9+/=]+)[;\n\r $]', decoded)
                if previousRaSid:
                    raSid = previousRaSid[0]
                else:
                    raSid = b64encode(os.urandom(40)).decode()
                response = self.config.welcomePage(raSid)
                log.debug("Sending %s" % response)
                try:
                    client_ssl.send(response)
                    client_ssl.close() # I think only the GET responses need to be closed right after the send
                except socket.error as e:
                    log.info("Error during sending response: %d" % e.errno)
                    client_ssl.close()
                return
            else:
                self.__createResponse(request, client_ssl)
                client_ssl.close()
                return     

        return

    def messageLoop(self):
        REQ_MSG_PONG = "PONG"
        REQ_MSG_NEW_DATA = "REQDATASOCK"
        while 1:
            try:
                data = self.control_ssl.read()
            except socket.error as e:
                if e.errno != socket.errno.ECONNRESET and e.errno != socket.errno.ECONNREFUSED:
                    raise
                break
            if data == b"":
                log.info("Receiving empty message")
                break
            if data.decode().startswith(REQ_MSG_NEW_DATA):
                log.debug("New data: %s" % data)
                threading.Thread(target=self.__handleDataSock, args=[data]).start()
            elif not data.decode().startswith(REQ_MSG_PONG):
                log.debug("[messageLoop] Message: %s" % data)
        log.info("Exiting messageLoop")
        return

    def run(self):
        try:
            keepAliveThread = None
            self.setGatewayName()
            self.connect()
            self.saveHostId()

            keepAliveThread = threading.Thread(target=self.__keepAlive, args=[])
            keepAliveThread.start()

            self.messageLoop()
        finally:
            if keepAliveThread is not None:
                keepAliveThread.do_run = False
                log.info("Waiting for keepAlive thread to stop...")
                keepAliveThread.join()

    @staticmethod
    def runForever(config):
        while 1:
            try:
                host = Host(config)
                host.run()
            except OSError as e:
                if e.errno != socket.errno.ECONNRESET and e.errno != socket.errno.ECONNREFUSED:
                    log.error(e.strerror)
                    log.error("Retrying in %d seconds..." % config.retryTimeout)
                    time.sleep(config.retryTimeout)        
            except ValueError as e:
                log.error(e.args)
                log.error("Retrying in %d seconds..." % config.retryTimeout)
                time.sleep(config.retryTimeout)

            log.info("Restarting...")
        return


class Register(object):
    """Registering the host at LogMeIn"""
    def __init__(self, config, deploymentCode: str):
        self.config = config
        self.deploymentCode = self.__parseDeploymentCode(deploymentCode)
    
    def hostRegister(self):
        registerUrl = "https://{}/myrahost/getdeployinfo.asp".format(self.config.homeSite)

        data = {
            "deployid": self.deploymentCode,
            "computerid": self.config.uniqueHostId(),
            "buildnumber": str(self.config.versionNum),
            "os": "linux",
            "hostdescription": self.config.description(),
            "hostname": self.config.hostName,
            "installmethod": 5,
            "cguid": ""
        }
        postData = urllib.parse.urlencode(data)
        log.debug(data)
        log.debug(postData)

        request = Request(registerUrl, postData.encode())
        response = urlopen(request)
        status = response.getcode()
        if status == 200:
            message = response.read().decode()
            if message.startswith("OK"):
                print("Success")
                self.__saveLicenseFile(message + "HOMESITE:{}\r\n".format(self.config.homeSite))
                return 0
            elif message.startswith("ERROR:31\r"):
                print("Deployment code is expired or already registered.\n"
                    "Please create a new one at https://{}/Deployment/ManageDeployments.aspx".format(self.config.homeSite))
            elif message.startswith("ERROR"):
                print("Error during getting the deploy info: {}".format(message))
            else:
                print("Unknown response")
                print(message)
        else:
            print("Error during getting deploy info: {}".format(status))
        return 1

    def __saveLicenseFile(self, data: str):
        if os.getuid() == 0:
            licenseFile = self.config.globalLicenseFile
            try:
                os.makedirs(os.path.dirname(self.config.globalLicenseFile), 0o700)
            except OSError as e:
                if e.errno != os.errno.EEXIST:
                    raise
                pass
        else:
            licenseFile = "./license.dat"
        try:
            with open(licenseFile, "w") as f:
                os.chmod(licenseFile, 0o600)
                cipher = AESCipher("4364b44b3aba62d8fa54b13398d7804d3fe53ea440e1cec280754b915ab573d447545a255abe0181")
                f.write(cipher.encrypt(data).decode())
        except Exception as e:
            log.error("Cannot save license file: {}\nExiting...".format(str(e)))
            sys.exit(1)

    def __parseDeploymentCode(self, deploymentCode: str) -> str:
        if "https" not in deploymentCode:
            return deploymentCode
        else:
            parsedDeploymentCode = re.findall(r'^https.*[&\?]c=(.[^&]*)', deploymentCode)
            if len(parsedDeploymentCode) == 0:
                log.error("URL doesn't contain deployment code")
                sys.exit(1)
            else:
                return parsedDeploymentCode[0]

def syslog_handle_exception(exc_type, exc_value, exc_traceback):
    """Redefine to log with our logger instead of printing to the sys.stderr"""
    log.exception("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

def main():
    config = Config()
    parser = ArgumentParser(description='Access Linux hosts from LogMeIn Central')
    parser.add_argument('--deployment-code', type=str,
                        help='Register the host to LogMeIn with a Deployment Code generated at\nhttps://{}/Deployment/ManageDeployments.aspx'.format(config.homeSite))
    parser.add_argument('--stdin', action='store_true',
                        help='Read license data from standard input')
    parser.add_argument('--syslog', action='store_true',
                        help='Use syslog for logging instead of stderr')
    args = parser.parse_args()

    if (args.syslog):
        log.basicConfig(level=config.getLoglevel(), format='logmein-host: %(threadName)s %(message)s', handlers=[logging.handlers.SysLogHandler("/dev/log")])
        sys.excepthook = syslog_handle_exception
    else:
        log.basicConfig(level=config.getLoglevel(), format='%(asctime)s %(threadName)s %(message)s')

    if args.deployment_code:
        register = Register(config, args.deployment_code)
        sys.exit(register.hostRegister())
    else:
        config.parseLicenseFile(args.stdin)
        Host.runForever(config)

if __name__ == "__main__":
    main()
