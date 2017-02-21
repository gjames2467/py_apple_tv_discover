"""Simple example that connects to a device with autodiscover."""

import sys
import pyatv
import asyncio
#NEW MODULE
#Make sure to pip install dnslib
from device_search import device_search


# Method that is dispatched by the asyncio event loop
@asyncio.coroutine
def print_what_is_playing(loop):
    print('Discovering devices on network...')
    try:

        atvs = yield from pyatv.scan_for_apple_tvs(loop, timeout=5)
        if len(atvs)==0:
            raise IndexError
        print('Connecting to {}'.format(atvs[0].address))
        atv = pyatv.connect_to_apple_tv(atvs[0], loop)

    except IndexError:
        """
            New module for device discovery below
        """
        print('auto discover failed')
        login_dict = device_search().login_info
        print(login_dict)
        details = pyatv.AppleTVDevice(
            login_dict['NAME'],
            login_dict['ADDRESS'],
            login_dict['HSGID'])

        atv = pyatv.connect_to_apple_tv(details,loop)



    try:
        playing = yield from atv.metadata.playing()
        print('Currently playing:')
        print(playing)

        # yield from atv.remote_control.play()
        # yield atv.remote_control.select()
    finally:
        # Do not forget to logout
        yield from atv.logout()


loop = asyncio.get_event_loop()
loop.run_until_complete(print_what_is_playing(loop))
