# py_apple_tv_discover

Just posted this to show an alternative device discovery method for pyatv (https://github.com/postlund/pyatv).
The two examples should show you how it works:
  1. autodiscover.py
    - This just uses the new alternative module (device search) when zeroconf fails.
  2. example_just_getting_login_data.py
    - just shows how the device_search module works.
    - it is setup to find apple tv but could be reconfigured for any MDNS service.
    - I used a lot of the code from Zeroconf.
