LogMeIn host software for Linux (Beta)
======================================

### Overview

The LogMeIn Host Software (Beta) is available for Linux.  
  
Each Linux host is displayed like any other host in your Computers list. When you connect to a Linux host, a remote terminal shell opens and it allows you to send commands to the host computer.

### Requirements

Python version 3.4+ is required with some PyPi dependencies. To install the dependencies run the following after cloning this repository:

```sh
$ pip3 install -r requirements.txt
```

### Installing the `logmein-host` for Linux

**Generate an Installation Package and retrieve the Deployment Code**
1.  In LogMeIn Central, go to the **Deployment** page.
2.  On the **Deployment** page, click **Add Installation Package**. The _Installation Package_ page is displayed.
3.  Fill in the necessary fields and select the appropriate options for the remote installation.
4.  Click **Save Settings**. The _Deploy Installation Package_ page is displayed.
5.  On the _Deploy Installation Package_ page, copy the **Installation Link**.  
    Example: `https://secure.logmein.com/i?l=en&c=01_bma2ecmmg4coyxou9oo6yhhvw0ewi3estniee`

**Register the host in the LogMeIn Central**  
Use the **Installation Link** or the deployment code itself:

```sh
# Use the whole url
$ python3 logmein-host/logmein-host.py --deployment-code 'https://secure.logmein.com/i?l=en&c=01_bma2ecmmg4coyxou9oo6yhhvw0ewi3estniee'

# or just the code
$ python3 logmein-host/logmein-host.py --deployment-code "01_bma2ecmmg4coyxou9oo6yhhvw0ewi3estniee"
```

### Running the host
Run `pytty`, the web terminal app that will connect to the localhost using *ssh*  and forward the *tty* to the browser:

```sh
$ python3 pytty/pytty.py &
```

Then run `logmein-host` which connects `pytty` to the LogMeIn gateways:

```sh
$ python3 logmein-host/logmein_host.py 
```

### License
Copyright (c) 2018 LogMeIn, Inc.

Licensed under the MIT License
