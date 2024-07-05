from __future__ import print_function
import frida
import sys
import os

def on_message(message, data):
        print("[%s] => %s" % (message, data))


def main(target_process):
    session = frida.attach(target_process)

    with open("aa.py.js", "r", encoding='UTF-8') as f:  # 打开文件
        script = session.create_script(f.read())

    script.on('message', on_message)
    script.load()
    try:
        sys.stdin.read()
    except:
        print('exiting')
    script.exports.exit()
    session.detach()

if __name__ == '__main__':
    main('War3.exe')