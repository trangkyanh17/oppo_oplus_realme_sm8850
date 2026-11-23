#!/usr/bin/env python3
"""Read-only X.509/GNU-build-ID provenance verification for Google GKI Image."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

def sha(b):
    return hashlib.sha256(b).hexdigest()

def symbols(p):
    found={}
    for ln in p.read_text(errors="replace").splitlines():
        row=ln.split(maxsplit=2)
        if len(row)==3 and row[2] in ("_text","__module_cert_start","__module_cert_end"):
            found[row[2]]=int(row[0],16)
    if not {"_text","__module_cert_start"}.issubset(found):
        raise ValueError("No _text or module certificate start in System.map")
    return found

def cert(blob,offset):
    if blob[offset]!=0x30:
        raise ValueError("Not an ASN.1 DER SEQUENCE at module certificate address")
    x=blob[offset+1]
    if x<=127:
        n=2;size=x
    else:
        count=x&0x7f
        if count not in (1,2,3,4):
            raise ValueError("Unrecognized DER length")
        n=2+count
        size=int.from_bytes(blob[offset+2:offset+n],"big")
    data=blob[offset:offset+n+size]
    with tempfile.NamedTemporaryFile(suffix=".der") as f:
        f.write(data);f.flush()
        info=subprocess.run(["openssl","x509","-inform","DER","-in",f.name,
                             "-noout","-subject","-issuer","-dates","-fingerprint","-sha256"],
                            capture_output=True,text=True)
        key=subprocess.run(["openssl","x509","-inform","DER","-in",f.name,
                            "-noout","-pubkey"],capture_output=True,text=True)
    if info.returncode or key.returncode:
        raise RuntimeError("OpenSSL X.509 parsing failed: "+info.stderr+key.stderr)
    return data,{"start":offset,"length":len(data),"sha256":sha(data),
                 "public_key_sha256":sha(key.stdout.encode()),
                 "info":info.stdout.strip()}

def different_gnu_build_id(a,b):
    signature=struct.pack("<III",4,20,3)+b"GNU\x00"
    offsets=[]
    pos=0
    while True:
        pos=a.find(signature,pos)
        if pos<0:break
        desc=pos+len(signature)
        if a[desc:desc+20]!=b[desc:desc+20]:
            offsets.append(desc)
        pos+=1
    if len(offsets)!=1:
        raise ValueError(f"Expected 1 differing GNU SHA-1 build-ID note; found {offsets}")
    return offsets[0]

def main():
    parser=argparse.ArgumentParser()
    for name in ("built","google","system-map","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    a=args.built.read_bytes()
    b=args.google.read_bytes()
    if len(a)!=len(b):
        raise ValueError("Images not equal size")
    sm=symbols(args.system_map)
    off=sm["__module_cert_start"]-sm["_text"]
    ca,ia=cert(a,off)
    cb,ib=cert(b,off)
    if len(ca)!=len(cb):
        raise ValueError("Different certificate lengths")
    note_off=different_gnu_build_id(a,b)
    cover=bytearray(len(a))
    cover[off:off+len(ca)]=b"\x01"*len(ca)
    cover[note_off:note_off+20]=b"\x02"*20
    counts={"certificate":0,"gnu_build_id":0,"other":0}
    for pos,(x,y) in enumerate(zip(a,b)):
        if x!=y:
            counts[{1:"certificate",2:"gnu_build_id"}.get(cover[pos],"other")]+=1
    ma=bytearray(a)
    mb=bytearray(b)
    for x in (ma,mb):
        x[off:off+len(ca)]=b"\x00"*len(ca)
        x[note_off:note_off+20]=b"\x00"*20
    output={
      "status":"X509_GNU_BUILD_ID_ANALYSIS_NOT_FLASH_QUALIFIED",
      "image_size":len(a),
      "built_sha256":sha(a),
      "google_sha256":sha(b),
      "byte_differences":counts,
      "normalized_images_identical":ma==mb,
      "normalized_sha256_built":sha(ma),
      "normalized_sha256_google":sha(mb),
      "module_signer_public_keys_identical":ia["public_key_sha256"]==ib["public_key_sha256"],
      "built_x509":ia,
      "google_x509":ib,
      "gnu_sha1_build_id":{"offset":note_off,"built":a[note_off:note_off+20].hex(),
                           "google":b[note_off:note_off+20].hex()},
      "stock_oneplus_boot_verified":False,
      "stock_oneplus_modules_verified":False,
      "safe_to_flash":False,
      "interpretation":"Only trust anchor certificate and its linked GNU build ID differ. Re-signing or copying Google public certificate bytes does not grant Google's private signing key."
    }
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(output,indent=2)+"\n")
    args.output.with_suffix(".txt").write_text("\n".join(f"{k}: {v}" for k,v in output.items())+"\n")
    print(json.dumps(output,indent=2))
    if not output["normalized_images_identical"] or counts["other"]!=0:
        raise SystemExit("Unexpected byte differences outside X509/build-ID regions")

if __name__=="__main__":
    main()
