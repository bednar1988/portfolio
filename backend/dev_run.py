import os
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BACKEND_DIR)

os.environ["DB_PATH"] = os.path.join(
    r"C:\Users\tomek\AppData\Local\Temp\claude\C--Users-tomek-repos\f0b1bf7b-30e9-411a-9f78-d002bbcd98d0\scratchpad",
    "portfolio_test.db"
)
os.environ["FRONTEND_DIR"] = os.path.join(BACKEND_DIR, "..", "frontend")

import uvicorn

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8711)
