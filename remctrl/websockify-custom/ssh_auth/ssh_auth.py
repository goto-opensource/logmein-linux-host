import os
import socket
import logging

from ssh2.session import Session
from ssh2.exceptions import SSH2Error, AuthenticationError
from websockify.auth_plugins import BasicHTTPAuth, AuthenticationError

class HTTPAuthWithSsh(BasicHTTPAuth):
    """Verifies Basic Auth headers by sshing to localhost"""

    def validate_creds(self, username, password):
        host = "127.0.0.1"
        port = 22
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))

            session = Session()
            session.handshake(sock)
            session.userauth_password(username, password)

            channel = session.open_session()
            channel.execute("true")
            channel.close()

            print("Successfully authenticated \"{}\" user.".format(username))

            return True
        except Exception as error:
            print("Error during authenticating \"{}\" user!".format(username))

            return False
