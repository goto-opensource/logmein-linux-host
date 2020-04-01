# Development Guide

## The architecture

The (simplified) application stack looks like this:
| Web browser (as client)  | LogMeIn Gateways | LogMeIn Linux Host (as remote host)                          |
| :---                     | :---             | :---                                                         |
| hterm js code            | secure websocket | logmein_host.py                                              |
|                          |                  | &nbsp; &nbsp; reverse-proxy.js (localhost:23820)             |
|                          |                  | &nbsp; &nbsp; &nbsp; &nbsp; pytty.py (localhost:23821)       |
| novnc js code            | secure websocket | logmein_host.py                                              |
|                          |                  | &nbsp; &nbsp; reverse-proxy.js (localhost:23820)             |
|                          |                  | &nbsp; &nbsp; &nbsp; &nbsp; websockify.py (localhost:23825)  | 
|                          |                  | &nbsp; &nbsp; &nbsp; &nbsp; vnc server (localhost:23826)     |

The `logmein_host` app connects to the Gateway and handles the incoming https requests. All the requests are
forwarded to the `reverse-proxy` app that sorts by the url to the target service.


## Requirements

Python version 3.4+ and Node.js 8+ are required. To install the dependencies run the following after cloning this repository:

```sh
$ pip3 install -r requirements.txt
$ npm install -g yarn                # if you don't have yarn installed
$ cd reverse-proxy
$ yarn 
```

## Register the host in the LogMeIn Central

Use the **Installation Link** or the deployment code it:

```sh
# Use the whole url:
$ python3 logmein_host/logmein_host.py --deployment-code 'https://secure.logmein.com/i?l=en&c=01_bma2ecmmg4coyxou9oo6yhhvw0ewi3estniee'

# or just the deployment code:
$ python3 logmein_host/logmein_host.py --deployment-code "01_bma2ecmmg4coyxou9oo6yhhvw0ewi3estniee"
```

## Running the host

Run `pytty`, the web terminal app that connects to the localhost using *ssh*  and forward the *tty* to the browser:

```sh
$ python3 pytty/pytty.py
```

Run `reverse-proxy` to sort the incoming https request to the target service -- e.g. pytty or novnc.

```sh
$ cd reverse-proxy
$ yarn serve
```

Run `websockify` to get connected to the vnc server:

```sh
$ openssl req -new -x509 -days 3650 -nodes -out "self.pem" \
            -keyout "self.pem" -subj '/CN=www.mydom.com/O=My Company Name LTD./C=US'
$ remctrl/websockify-custom/launch.sh --vnc localhost:5900 \
            --listen 23825 --web remctrl/noVNC-branding --cert self.pem
```

Then run `logmein_host` which connects `pytty` and `websockify` to the LogMeIn gateways (through the `reverse-proxy`):

```sh
$ python3 logmein_host/logmein_host.py 
```

