from typing import Dict, List, Set
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

from pprint import pprint

COV_ADDR:Set[int] = set()
cov_idx = 0

def msg_callback(message:Dict[str, Dict[str, Dict[str, str]]], data):
    #print(f'recv action {message["payload"]["action"]}')
    #pprint(message)
    if message["payload"]["action"] == "create_global":
        for k, v in message["payload"]["val"].items():
            global_name = k
            global_val = eval(v)
            globals()[global_name] = global_val
    elif message["payload"]["action"] == "uuid":
        uuid, it =list(message["payload"]["val"].items())[0]
        global UUID_SAVE
        UUID_SAVE.update({uuid:it})
    elif message["payload"]["action"] == "cov":
        global COV_ADDR
        global cov_idx
        cov_idx += 1
        COV_ADDR.add(message["payload"]["val"])
        #if cov_idx % 20 == 0:
        #    print(len(COV_ADDR))

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
    
def list_asm_methods():
    script.post({'type': 'input', 'payload': {
        "action":"listAsmMethods",
        "param":{}
    }})

def wait_for_global_creation(global_name:str):
    while global_name not in globals():
        sleep(0.1)

def create_cov_callback(ptr:int):
    post_uuid = str(uuid4())
    script.post({'type': 'input', 'payload': {
        "action":"createCb",
        "param":{
            "addr": ptr,
            "loc": "",
            "uuid":post_uuid
        }
    }})
    wait_for_uuid(post_uuid)

def ck_contains_prefix(s:str, pre:List[str])->bool:
    for p in pre:
        if s.startswith(p):
            return True
    return False

btns = [
    "BattleButton",
    "WorkshopButton",
    "CardsButton",
    "StoreButton",
]

script.on('message', msg_callback)
script.load()
sleep(1) # 讓子彈飛一會兒
list_asm_methods()

#press_btn_instance(btn_mappings["WorkshopButton"])
wait_for_global_creation("ASM_METHODS")
#with open("yourlogfile.log", "w") as log_file:
#    pprint(ASM_METHODS, log_file)
IGNORE_PREFIX_LIST = [
    "LitJson",
    "I2",
    "IronSourceJSON",
    "TapjoyUnity",
    "UnityEngine",
    "GooglePlayGames",
    "AppsFlyerSDK",
    "AFMiniJSON"
]

all_methods = 0
for k, v in ASM_METHODS.items():
    if int(v, 16) == 0:
        continue
    if ck_contains_prefix(k, IGNORE_PREFIX_LIST):
        continue
    print(f"hook {k}")
    create_cov_callback(v)
    all_methods += 1
print("all_methods cnt: ", all_methods)
btn_mappings = { i:query_btn_instance(i) for i in btns }
print("[start pressing after 3 sec...]")
sleep(3)
for k, v in btn_mappings.items():
    print(f"[press {k}]")
    press_btn_instance(v)
    sleep(1)
sleep(10) # 讓子彈飛一會兒
print(f"=====================================")
print(f"total coverage: {len(COV_ADDR)} / {all_methods} ({len(COV_ADDR) / all_methods})")
print(f"=====================================")

input("[]")
sess.detach()