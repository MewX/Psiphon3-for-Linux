import os, json

# Delete 'server_list' if exists
if os.path.exists("server_list"):
    os.remove("server_list")

# Download 'server_list' and convert server_list to psi_client.dat 
url ="https://psiphon3.com/server_list"
os.system('wget ' + url)

dat = {}
dat["propagation_channel_id"] = "FFFFFFFFFFFFFFFF"
dat["sponsor_id"] = "FFFFFFFFFFFFFFFF"
dat["servers"] = json.load(open('server_list'))['data'].split()
json.dump(dat, open('psi_client.dat', 'w'))

