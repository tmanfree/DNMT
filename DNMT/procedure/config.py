### A copy of config.py from capt(Creator: Craig Tomkow)
### load_sw_base_conf() will probably be merged into that one


# Config handler module (singleton)

# system imports
import configparser
import os


#add this to the capt config.py with a different name
def load_sw_base_conf():
    config = configparser.ConfigParser()
    # config.read(os.path.join(os.path.expanduser('~'), "config.text"))
    #config.read("config.text") #local file reading
    config.read(os.path.abspath(os.path.join(os.sep, 'usr', 'lib', 'capt', 'config.text')))

    global username
    global password
    global enable_pw
    global ro
    global rw
    global logpath
    global port_label_email
    global port_label_pw
    global ipam_un
    global ipam_pw

    username = config['SWITCHCRED']['username']
    password = config['SWITCHCRED']['password']
    enable_pw = config['SWITCHCRED']['enable']
    ro = config['SNMP']['ro']
    rw = config['SNMP']['rw']
    logpath = config['PATH']['logpath']
    port_label_email = config['PORTLABEL']['email']
    port_label_pw = config['PORTLABEL']['password']
    ipam_un = config['IPAMCRED']['username']
    ipam_pw =  config['IPAMCRED']['password']

