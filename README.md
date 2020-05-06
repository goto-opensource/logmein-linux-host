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

**Register the host in LogMeIn Central**

Use the **Installation Link** or the deployment code itself:
```sh
sudo snap set logmein-host 'deploy-code=<install link>'
```

Make sure that SSH server is installed on your computer:
```sh
sudo apt install openssh-server
```

### Enable the remote desktop control feature

This feature is under development. To get the current state you have to switch to the "edge" channel:

```sh
sudo snap refresh --edge logmein-host
```

You can enable and configure the VNC-based remote desktop control with the following:
```sh
sudo /snap/logmein-host/current/setup-vnc.sh --install
```

**Note:** You must restart your computer after configuring the feature.

The snap package contains a pre-installed `x11vnc` server. However, on some systems where there is another VNC server
installed, the built-in x11vnc server can be replaced. This can be detected during the configuration or can be forced with the `--use-default-vnc-port` parameter.

```sh
pi@raspberrypi:~ $ /snap/logmein-host/current/setup-vnc.sh --help
Usage: setup-vnc.sh [--install | --uninstall] [--use-default-vnc-port]

Setting up the LogMeIn VNC module.

    --install               Installs the necessary services and
                            configures the parameters
    --uninstall             Removes the services and all the
                            configuration
    --use-default-vnc-port  Use VNC server running at
                            localhost:5900

pi@raspberrypi:~ $ sudo /snap/logmein-host/current/setup-vnc.sh --install
It seems you have a VNC server running on localhost:5900. Would you like to use that? [yes/no] yes
```

#### Limitations
You must disable _Wayland display manager_. To do so edit `/etc/gdm3/custom.conf` and set `WaylandEnable=false`:

```
[daemon]
# Uncoment the line below to force the login screen to use Xorg
WaylandEnable=false
```

### Contribute to `logmein-host`

Read the [development guide](DEVELOPMENT.md) if you're interested in helping out.

### License

Copyright (c) 2018-2020 LogMeIn, Inc.

Licensed under the MIT License
