"""Target for rehearsing pointer scans.

Keeps gold in a fixed unmanaged buffer reached through a couple of indirections, so
there is a real chain to find rather than a bare global. Prints the true address so a
test can check the scanner landed on the right place.
"""
import ctypes
import os
import sys


class Player(ctypes.Structure):
    _fields_ = [("health", ctypes.c_int32),
                ("gold", ctypes.c_int32),
                ("level", ctypes.c_int32)]


class World(ctypes.Structure):
    _fields_ = [("tick", ctypes.c_int64),
                ("player", ctypes.POINTER(Player))]


# Held in module globals so the objects stay alive for the whole run.
PLAYER = Player(health=100, gold=500, level=7)
WORLD = World(tick=0, player=ctypes.pointer(PLAYER))
WORLD_PTR = ctypes.pointer(WORLD)

gold_address = ctypes.addressof(PLAYER) + Player.gold.offset

print("=" * 64)
print(" MemReader pointer-scan target")
print("=" * 64)
print(f" PID          : {os.getpid()}")
print(f" gold address : {hex(gold_address)}")
print(f" gold value   : {PLAYER.gold}")
print(f" world  at    : {hex(ctypes.addressof(WORLD))}")
print("=" * 64)
sys.stdout.flush()

while True:
    try:
        raw = input("\n> ").strip()
    except EOFError:
        break
    if raw.lower() in ("q", "quit", "exit"):
        break
    if raw.startswith("spend"):
        PLAYER.gold -= int(raw.split()[1])
    elif raw.startswith("set"):
        PLAYER.gold = int(raw.split()[1])

    print(f"  gold = {PLAYER.gold} at {hex(gold_address)}")
    sys.stdout.flush()
