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

"""Web terminal running on localhost."""

import logging
import logging.handlers
import tornado.escape
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.websocket
from tornado.concurrent import run_on_executor
from tornado.queues import Queue
from tornado import gen
from concurrent.futures import ThreadPoolExecutor
import sys
import os.path
import pexpect
from binascii import hexlify
from contextlib import suppress
import uuid

from tornado.options import define, options

define("port", default=23827, help="run on the given port", type=int)
define("syslog", default=False, help="use syslog for logging instead of stderr", type=bool)

MAX_WORKERS = 4
sshCommand = \
    """bash -c '
        set -e
        while [ -z \"${username}\" ]; do
            echo -n \"localhost login: \"
            read username
        done
        ssh -l \"${username}\" -F /dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
            -o PreferredAuthentications=password,keyboard-interactive localhost'
    """
# To simplify the testing:
# sshCommand = """/bin/bash --posix"""

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/term/", MainHandler),
            (r"/termsocket", TermSocketHandler),
            (r'/term/static/(.*)', tornado.web.StaticFileHandler, {'path': os.path.join(os.path.dirname(__file__), "static")}),
        ]
        settings = dict(
            cookie_secret=hexlify(os.urandom(40)).decode(),
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            #static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            websocket_ping_interval=3,
            websocket_ping_timeout=7,
            no_keep_alive=False,
            # xheaders=True,     # In case there are connectivity errors
            # debug=True         # To debug and live reload
        )
        super(Application, self).__init__(handlers, **settings)


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html")

class TermSocketHandler(tornado.websocket.WebSocketHandler):
    def initialize(self):
        logging.info("{} - handler initialize.".format(hex(id(self))))
        self.ssh_queue = tornado.queues.Queue()
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def get_compression_options(self):
        # Non-None enables compression with default options.
        return {}

    @gen.coroutine
    @run_on_executor(executor='executor')
    def run_ssh(self):
        """ Coroutine to run ssh on a new thread and read its terminal data to the queue """
        logging.info("{} - run_ssh starting new process...".format(hex(id(self))))
        os.environ["TERM"] = "xterm-256color"
        os.environ["COLS"] = "80"
        os.environ["ROWS"] = "30"
        self.ssh = pexpect.spawn(sshCommand, encoding="utf-8")
        while True:
            data = os.read(self.ssh.child_fd, 1024)
            if data == b"":
                break
            decoded = data.decode("utf-8", "backslashreplace")
            self.ssh_queue.put_nowait(decoded)
        logging.info("{} - run_ssh ended.".format(hex(id(self))))


    @gen.coroutine
    def send_ssh_output(self):
        """ Coroutine that reads the queue and forwards to the browser """
        while True:
            data = yield self.ssh_queue.get()
            if not data:
                break
            message = tornado.escape.json_encode({ "event": "output", "data": data })
            try:
                yield self.write_message(message)
            except tornado.websocket.WebSocketClosedError:
                break

    @gen.coroutine
    def open(self):
        """ Coroutine that starts the whole flow on new connection """
        logging.info("{} - new connection.".format(hex(id(self))))
        self.run_ssh()
        self.send_ssh_output()

    def on_close(self):
        """ Handler to terminate the ssh connection on close """
        logging.info("{} - connection closed.".format(hex(id(self))))
        with suppress(Exception):
            self.ssh.terminate()

    @run_on_executor(executor='executor')
    def on_message(self, message):
        """ Handle new data from the client.\n
            It runs on the same thread where the ssh process started to gain some speed-up. """
        parsed = tornado.escape.json_decode(message)
        if parsed["event"] == "input":
            try:
                os.write(self.ssh.child_fd, parsed["message"].encode())
            except OSError:
                self.close()
        elif parsed["event"] == "resize":
            with suppress(Exception):
                self.ssh.setwinsize(parsed["message"]["row"], parsed["message"]["col"])

def syslog_handle_exception(exc_type, exc_value, exc_traceback):
    """Redefine to log with our logger instead of printing to the sys.stderr"""
    logging.exception("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

def main_func():
    # Switch off tornado's builtin logging
    tornado.options.options.logging = None
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port, address='127.0.0.1', no_keep_alive=False)
    if options.syslog:
        logging.getLogger("")
        logging.basicConfig(level=os.getenv("LOGLEVEL", "INFO"), format='pytty: %(threadName)s %(message)s', handlers=[logging.handlers.SysLogHandler("/dev/log")])
        sys.excepthook = syslog_handle_exception
    else:
        logging.basicConfig(level=os.getenv("LOGLEVEL", "INFO"), format='%(asctime)s %(threadName)s %(message)s')
    logging.info("Starting pytty on port {}...".format(options.port))
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main_func()
