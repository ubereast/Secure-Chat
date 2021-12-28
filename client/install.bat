@echo off
py -m pip uninstall pycrypto
py -m pip uninstall crypto 
py -m pip install pycryptodome
py -m pip install uuid
py -m pip install pyyaml
py -m pip install bson
py -m pip install windows-curses
py -m pip install colorama
py -m pip install pynput