"""python pipeline.py  -> runs Sentinel every 2s. On a detection it runs Bloodhound, then Blacksmith."""
import time
from generator import DB, Blocks
from agents import Ctx, sentinel_scan, handle
from llm import Akash

def main():
    db = DB()
    blocks = Blocks(db)
    ctx = Ctx(db.c, None, blocks)
    ctx.llm = Akash(ctx.log)
    print("AEGIS pipeline running. Waiting for threats...")
    pending = []                       # incident reports, written once Sentinel has nothing new to handle
    while True:
        blocks.refresh()
        try:
            incs = sentinel_scan(ctx)
            for inc in incs:
                pending.append(handle(ctx, inc)[1])
            if not incs:
                while pending:
                    pending.pop(0)()
        except Exception as e:
            print("pipeline error:", repr(e))
        time.sleep(2)

if __name__ == "__main__":
    main()
