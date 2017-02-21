from device_search.methods.get_login_info import normalize_interface_choice,InterfaceChoice
import netifaces
data=[]
for x in netifaces.interfaces():
    try:
        tmp_interface=netifaces.ifaddresses(x).get(2)[0].get('addr')
        if tmp_interface!=None:
            data.append(tmp_interface)
    except:
        pass
print(data)
print(normalize_interface_choice(InterfaceChoice.All,2))