from device_search.methods import *

class device_search():
    def __init__(self):
        """
            returns an object with two properties for the apple tv
            the decivces TCP name aka app_tv_name
            all the infor you need to create a session ot the apple tv
        """
        self.app_tv_name=device_finder()
        self.login_info=get_login_info(self.app_tv_name)