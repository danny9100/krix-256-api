from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from krix import encrypt, decrypt

app = FastAPI(title="KRIX-256 API", version="1.0")

class EncReq(BaseModel):
    plaintext: str
    key: str

class DecReq(BaseModel):
    ciphertext: str
    key: str

@app.get("/")
def root():
    return {
        "cipher": "KRIX-256",
        "status": "ok",
        "endpoints": ["/encrypt", "/decrypt", "/docs"]
    }

@app.post("/encrypt")
def do_encrypt(req: EncReq):
    try:
        return {"ciphertext": encrypt(req.plaintext, req.key)}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/decrypt")
def do_decrypt(req: DecReq):
    try:
        return {"plaintext": decrypt(req.ciphertext, req.key)}
    except Exception as e:
        raise HTTPException(400, "Decryption failed: " + str(e))