LogMeIn host software for Linux (Beta)
======================================
[![Snap Status](https://build.snapcraft.io/badge/LogMeIn/logmein-linux-host.svg)](https://build.snapcraft.io/user/LogMeIn/logmein-linux-host)

### Overview

The LogMeIn Host Software (Beta) is available for Linux.  
  
Each Linux host is displayed like any other host in your Computers list. When you connect to a Linux host, a remote terminal shell opens and it allows you to send commands to the host computer.

### Installing the `logmein-host` for Linux

You must have snapd installed. To download snapd, visit https://docs.snapcraft.io/core/install.
On your Linux device, open a Terminal and use the following command:
```sh
sudo snap install logmein-host
```

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
sudo snap set logmein-host 'deploy-code=<install link>'
```

### Contribute to `logmein-host`

Read the [development guide](DEVELOPMENT.md) if you're interested in helping out.

### License

Copyright (c) 2018-2020 LogMeIn, Inc.

Licensed under the MIT License
