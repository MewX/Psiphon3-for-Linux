# Psiphon3-for-Linux
Part of Psiphon3 repo, for Linux operating system. (python, C)
Full repo is [here](https://bitbucket.org/psiphon/psiphon-circumvention-system)

# Make openssh first

You will need to build OpenSSH 5.9p1 that supports obfuscation: 

    cd openssh-5.9p1/
    ./configure
    make

and copy ssh binary from `openssh-5.9p1/` to `pyclient/`

# Usage

- update server list first

    cd pyclient
    python update.py

- run proxy, you will see `Your SOCKS proxy is now running at 127.0.0.1:1080`

    python psi_client.py

- set proxy configuration in apps (Android Studio for example)

    select "SOCKS"
    fill "Address" and "Port"
    press "OK"

For more details visit related Google Group discussion at
https://groups.google.com/forum/#!searchin/psiphon3-developers/python$20/psiphon3-developers/cb8CW7Y98nI/BRx7-cIQ7C8J
