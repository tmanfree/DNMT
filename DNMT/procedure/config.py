### A copy of config.py from capt(Creator: Craig Tomkow)
### load_sw_base_conf() will probably be merged into that one


# Config handler module (singleton)

# system imports
import configparser
import os


#add this to the capt config.py with a different name
def load_sw_base_conf():
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.expanduser('~'), "config.text"))
    #config.read("config.text") #local file reading

    global username
    global password
    global enable_pw
    global ro
    global rw
    global logpath

    username = config['SWITCHCRED']['username']
    password = config['SWITCHCRED']['password']
    enable_pw = config['SWITCHCRED']['enable']
    ro = config['SNMP']['ro']
    rw = config['SNMP']['rw']
    logpath = config['PATH']['logpath']

