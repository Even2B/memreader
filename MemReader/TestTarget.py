"""Practice target for MemReader.

Pretends to be a tiny game: it holds gold, health and a player name in memory, and
lets you spend or take damage. Use it to rehearse three workflows -

  Known value   : scan gold for 500, change it, Next Scan.
  Unknown value : Snapshot, spend 50, then filter "went down by" 50.
  Correlation   : watch gold/health/frame_tick together, mark each 'spend',
                  and confirm gold scores highest while frame_tick (which
                  changes on its own, unrelated to any mark) gets buried.
"""
import ctypes
import os
import sys
import threading
import time

gold = ctypes.c_int32(500)
health = ctypes.c_int32(100)
name = ctypes.create_unicode_buffer("PLAYER_ONE", 64)

# A value that changes constantly for reasons that have nothing to do with the
# player - a frame counter, an animation clock, a network heartbeat. Real games
# are full of these, and they're exactly what the correlation detector needs to
# tell apart from something that actually reacts to a marked event.
frame_tick = ctypes.c_int32(0)


def _tick_forever():
    while True:
        frame_tick.value += 1
        time.sleep(0.05)


threading.Thread(target=_tick_forever, daemon=True).start()


def show():
    print(f"  gold = {gold.value}   health = {health.value}   "
          f"frame_tick = {frame_tick.value}   name = {name.value!r}")
    sys.stdout.flush()


print("=" * 64)
print(" MemReader practice target - a pretend game")
print("=" * 64)
print(f" PID   : {os.getpid()}")
print(f" gold  : {gold.value}  (true address {hex(ctypes.addressof(gold))})")
print(f" health: {health.value}  (true address {hex(ctypes.addressof(health))})")
print(f" tick  : {frame_tick.value}  (true address {hex(ctypes.addressof(frame_tick))}, "
      f"changes on its own every 50ms - a noise decoy)")
print()
print(" commands:  spend <n>   hurt <n>   set <n>   show   q")
print()
print(" Unknown-value drill: Snapshot in MemReader, then 'spend 50' here,")
print(" then filter \"went down by\" 50. That is how you find money in a real game.")
print("=" * 64)

while True:
    try:
        raw = input("\n> ").strip()
    except EOFError:
        break

    if raw.lower() in ("q", "quit", "exit"):
        break

    parts = raw.split()
    cmd = parts[0].lower() if parts else "show"
    arg = parts[1] if len(parts) > 1 else None

    try:
        if cmd == "spend":
            gold.value -= int(arg)
        elif cmd == "hurt":
            health.value -= int(arg)
        elif cmd == "set":
            gold.value = int(arg)
        elif cmd in ("show", ""):
            pass
        else:
            print("  commands: spend <n> | hurt <n> | set <n> | show | q")
            continue
    except (TypeError, ValueError):
        print("  that command needs a number")
        continue

    show()
