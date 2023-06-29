from typing import Dict
import frida
from uuid import uuid4
from time import sleep
import threading

PROD_SCRIPT_PATH = r"Il2CppHookScripts\Il2cppHook\_Ufunc.js"
def get_frida_script()->str:
    with open(PROD_SCRIPT_PATH, "r", encoding="utf-8") as fp:
        return fp.read()

dev = frida.get_usb_device()
sess = dev.attach(target=dev.enumerate_processes()[0].pid)
script = sess.create_script(get_frida_script())

UUID_SAVE = {}

def msg_callback(message:Dict[str, Dict[str, Dict[str, str]]], data):
    print("recv: ", message)
    if message["payload"]["action"] == "create_global":
        for k, v in message["payload"]["val"].items():
            global_name = k
            global_val = v
            globals()[global_name] = int(global_val, 16) # created globals shall all be ptrs? TBD
    elif message["payload"]["action"] == "uuid":
        uuid, it =list(message["payload"]["val"].items())[0]
        global UUID_SAVE
        UUID_SAVE.update({uuid:it})

def wait_for_uuid(uuid:str):
    global UUID_SAVE
    while uuid not in UUID_SAVE:
        sleep(0.1)
    return UUID_SAVE.pop(uuid)

def query_func_addr(class_name:str, function_name:str, arg_count:int, image_name="Assembly-CSharp")->int:
    post_uuid = str(uuid4())
    script.post({'type': 'input', 'payload': {
        "action":"searchFunc",
        "param":{
            "imageName": image_name,
            "className": class_name,
            "functionName": function_name,
            "argsCount": arg_count,
            "uuid": post_uuid
        }
    }})
    res = int(wait_for_uuid(post_uuid), 16)
    #print(f"got addr : {hex(res)}")
    return res

def query_btn_instance(name:str)->int:
    post_uuid = str(uuid4())
    script.post({'type': 'input', 'payload': {
        "action":"findBtn",
        "param":{
            "name": name,
            "uuid": post_uuid
        }
    }})
    return int(wait_for_uuid(post_uuid), 16)

def press_btn_instance(ptr:int):
    script.post({'type': 'input', 'payload': {
        "action":"pressBtn",
        "param":{
            "addr": ptr,
        }
    }})
    

btns = [
    "BattleButton",
    "WorkshopButton",
    "CardsButton",
    "StoreButton",
]

script.on('message', msg_callback)
script.load()
btn_mappings = { i:query_btn_instance(i) for i in btns }
press_btn_instance(btn_mappings["WorkshopButton"])
input("[]")
sess.detach()