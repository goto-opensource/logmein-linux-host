## Development Guide

## Requirements

Python version 3.4+ and Node.js 8+ are required. To install the dependencies run the following after cloning this repository:

```sh
$ pip3 install -r requirements.txt
$ npm install -g yarn                # if you don't have yarn installed
$ cd reverse-proxy
$ yarn 
```

## Register the host in the LogMeIn Central

Use the **Installation Link** or the deployment code itself:

```sh
# Use the whole url
$ python3 logmein_host/logmein_host.py --deployment-code 'https://secure.logmein.com/i?l=en&c=01_bma2ecmmg4coyxou9oo6yhhvw0ewi3estniee'

# or just the code
$ python3 logmein_host/logmein_host.py --deployment-code "01_bma2ecmmg4coyxou9oo6yhhvw0ewi3estniee"
```

## Running the host

Run `pytty`, the web terminal app that will connect to the localhost using *ssh*  and forward the *tty* to the browser:

```sh
$ python3 pytty/pytty.py &
```

Then run `logmein_host` which connects `pytty` to the LogMeIn gateways:

```sh
$ python3 logmein_host/logmein_host.py 
```
