// Copyright (c) 2014 Krishna Srinivas
// Copyright (c) 2018 LogMeIn, Inc.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy 
// of this software and associated documentation files (the "Software"), to deal 
// in the Software without restriction, including without limitation the rights 
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
// copies of the Software, and to permit persons to whom the Software is 
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all 
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
// SOFTWARE.

var term;
var buf = '';

function Pytty(argv) {
    this.argv_ = argv;
    this.io = null;
    this.pid_ = -1;
}

Pytty.prototype.run = function() {
    this.io = this.argv_.io.push();

    this.io.onVTKeystroke = this.sendString_.bind(this);
    this.io.sendString = this.sendString_.bind(this);
    this.io.onTerminalResize = this.onTerminalResize.bind(this);
}

Pytty.prototype.sendString_ = function(str) {
    updater.emit("input", str);
};

Pytty.prototype.onTerminalResize = function(col, row) {
    updater.emit("resize", { 
        col: col, 
        row: row 
    });
};

var updater = {
    socket: null,

    start: function() {
        var url = "ws:";
        if (location.protocol === "https:") {
            url = "wss:";
        }
        url += "//" + location.host + "/term/termsocket";
        updater.socket = new WebSocket(url);
        updater.socket.binaryType = "arraybuffer";

        updater.socket.onopen = function() {
            lib.init(function() {
                hterm.defaultStorage = new lib.Storage.Local();
                term = new hterm.Terminal();
                window.term = term;
                term.decorate(document.getElementById('terminal'));
        
                term.setCursorPosition(0, 0);
                term.setCursorVisible(true);
                term.prefs_.set('ctrl-c-copy', true);
                term.prefs_.set('ctrl-v-paste', true);
                term.prefs_.set('use-default-window-copy', true);
        
                term.runCommandClass(Pytty, document.location.hash.substr(1));
                
                updater.emit("resize", {
                    col: term.screenSize.width,
                    row: term.screenSize.height
                });
        
                if (buf && buf != '')
                {
                    term.io.writeUTF16(buf);
                    buf = '';
                }
            });
        }

        updater.socket.onmessage = function(messageEvent) {
            parsed = JSON.parse(messageEvent.data);
            if (parsed.event === "output") {
                decoded = parsed.data;
                if (!term) {
                    buf += decoded;
                    return;
                }
                term.io.writeUTF16(decoded);
            }
        }

        updater.socket.onclose = function() {
            term.io.writeUTF16("\r\nConnection closed.\r\n");
            updater.socket = null;
        }
    },

    emit: function(type, obj) {
        if (updater.socket != null) {
            updater.socket.send(JSON.stringify({
                "event": type, 
                "message": obj
            }));    
        }   
    }
};


(function() {
    updater.start();
})();
