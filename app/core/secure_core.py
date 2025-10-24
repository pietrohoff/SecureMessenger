
import os, json, time, uuid, sqlite3, base64
from datetime import datetime
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

DEFAULT_DB = os.environ.get("SM_DB", os.path.join(os.path.dirname(__file__), "..", "data", "secure_messenger.db"))

def get_conn(db_path: str = None):
    db = db_path or DEFAULT_DB
    os.makedirs(os.path.dirname(db), exist_ok=True)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        privkey_pem BLOB NOT NULL,
        cert_pem BLOB NOT NULL
    );""")
    cur.execute("""CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        subject TEXT NOT NULL,
        body_hash_hex TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        aad_json TEXT NOT NULL,
        sig_hex TEXT NOT NULL
    );""")
    cur.execute("""CREATE TABLE IF NOT EXISTS envelopes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        msg_id INTEGER NOT NULL,
        recipient TEXT NOT NULL,
        enc_key_b64 TEXT NOT NULL,
        iv_b64 TEXT NOT NULL,
        tag_b64 TEXT NOT NULL,
        ciphertext_b64 TEXT NOT NULL,
        FOREIGN KEY(msg_id) REFERENCES messages(id)
    );""")
    cur.execute("""CREATE TABLE IF NOT EXISTS nonces(
        nonce TEXT PRIMARY KEY,
        timestamp INTEGER NOT NULL
    );""")
    cur.execute("""CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        event TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        sig_hex TEXT NOT NULL
    );""")
    cur.execute("""CREATE TABLE IF NOT EXISTS ca(
        id INTEGER PRIMARY KEY CHECK (id=1),
        ca_privkey_pem BLOB NOT NULL,
        ca_cert_pem BLOB NOT NULL
    );""")
    conn.commit()

def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data);  return h.finalize()

def load_private_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)

def load_certificate(pem: bytes):
    return x509.load_pem_x509_certificate(pem)

def ensure_ca(conn: sqlite3.Connection):
    row = conn.execute("SELECT ca_privkey_pem, ca_cert_pem FROM ca WHERE id=1").fetchone()
    if row: return row["ca_privkey_pem"], row["ca_cert_pem"]
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini-AC Didatica"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Mini-AC Didatica Root"),
    ])
    ca_cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow().replace(year=datetime.utcnow().year + 10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256()))
    ca_priv_pem = ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    conn.execute("INSERT INTO ca(id, ca_privkey_pem, ca_cert_pem) VALUES (1, ?, ?)", (ca_priv_pem, ca_cert_pem))
    conn.commit()
    return ca_priv_pem, ca_cert_pem

def issue_user_cert(ca_priv_pem: bytes, ca_cert_pem: bytes, username: str, user_pubkey):
    ca_key = load_private_key(ca_priv_pem)
    ca_cert = load_certificate(ca_cert_pem)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMessenger Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(user_pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow().replace(year=datetime.utcnow().year + 3))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)

def log_event(conn: sqlite3.Connection, event: str, payload: dict):
    ca_priv_pem, _ = ensure_ca(conn)
    ca_key = load_private_key(ca_priv_pem)
    ts = int(time.time())
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    digest = sha256(payload_json + ts.to_bytes(8, "big"))
    sig = ca_key.sign(
        digest,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    conn.execute("INSERT INTO audit(ts, event, payload_json, sig_hex) VALUES (?, ?, ?, ?)",
                 (ts, event, payload_json.decode(), sig.hex()))
    conn.commit()

def verify_audit(conn: sqlite3.Connection) -> bool:
    _, ca_cert_pem = ensure_ca(conn)
    pub = load_certificate(ca_cert_pem).public_key()
    ok = True
    from cryptography.exceptions import InvalidSignature
    for r in conn.execute("SELECT ts, payload_json, sig_hex FROM audit ORDER BY id"):
        ts = r["ts"]
        payload_json = r["payload_json"].encode()
        digest = sha256(payload_json + int(ts).to_bytes(8, "big"))
        sig = bytes.fromhex(r["sig_hex"])
        try:
            pub.verify(sig, digest,
                asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
                hashes.SHA256())
        except InvalidSignature:
            ok = False; break
    return ok

def add_user(conn: sqlite3.Connection, name: str):
    ca_priv_pem, ca_cert_pem = ensure_ca(conn)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    priv_pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PrivateFormat.PKCS8,
                                 encryption_algorithm=serialization.NoEncryption())
    cert_pem = issue_user_cert(ca_priv_pem, ca_cert_pem, name, key.public_key())
    conn.execute("INSERT INTO users(name, privkey_pem, cert_pem) VALUES (?, ?, ?)", (name, priv_pem, cert_pem))
    conn.commit()
    log_event(conn, "user_add", {"name": name})

def list_users(conn: sqlite3.Connection):
    return [r["name"] for r in conn.execute("SELECT name FROM users ORDER BY name")]

def get_user_material(conn: sqlite3.Connection, name: str):
    row = conn.execute("SELECT privkey_pem, cert_pem FROM users WHERE name=?", (name,)).fetchone()
    if not row: raise ValueError("Usuário não encontrado")
    return row["privkey_pem"], row["cert_pem"]

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    if aad: encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def aes_gcm_decrypt(key: bytes, iv: bytes, tag: bytes, ciphertext: bytes, aad: bytes):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    if aad: decryptor.authenticate_additional_data(aad)
    return decryptor.update(ciphertext) + decryptor.finalize()

def rsa_oaep_encrypt(pubkey, data: bytes) -> bytes:
    return pubkey.encrypt(
        data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

def rsa_oaep_decrypt(privkey, data: bytes) -> bytes:
    return privkey.decrypt(
        data,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

def rsa_pss_sign(privkey, data_hash: bytes) -> bytes:
    return privkey.sign(
        data_hash,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def rsa_pss_verify(pubkey, signature: bytes, data_hash: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        pubkey.verify(
            signature, data_hash,
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        ); return True
    except InvalidSignature:
        return False

def ensure_nonce_once(conn: sqlite3.Connection, nonce: str, timestamp: int):
    if conn.execute("SELECT 1 FROM nonces WHERE nonce=?", (nonce,)).fetchone():
        raise ValueError("Nonce já utilizado")
    conn.execute("INSERT INTO nonces(nonce, timestamp) VALUES (?, ?)", (nonce, timestamp)); conn.commit()

def send_message(conn: sqlite3.Connection, sender: str, recipients: list, subject: str, body: str) -> int:
    if not recipients: raise ValueError("Informe ao menos um destinatário")
    sender_priv_pem, sender_cert_pem = get_user_material(conn, sender)
    sender_key = load_private_key(sender_priv_pem)
    sender_cert = load_certificate(sender_cert_pem)
    _, ca_cert_pem = ensure_ca(conn)
    ca_cert = load_certificate(ca_cert_pem)
    if sender_cert.issuer != ca_cert.subject: raise ValueError("Cert do remetente não emitido pela CA")

    ts = int(time.time()); nonce = str(uuid.uuid4())
    ensure_nonce_once(conn, nonce, ts)
    aad = {"sender": sender, "recipients": recipients, "subject": subject, "timestamp": ts, "nonce": nonce}
    aad_json = json.dumps(aad, separators=(",", ":"), sort_keys=True).encode()

    body_bytes = body.encode()
    body_digest = sha256(body_bytes)
    signature = rsa_pss_sign(sender_key, body_digest)

    aes_key = os.urandom(32)
    iv, ciphertext, tag = aes_gcm_encrypt(aes_key, body_bytes, aad_json)

    cur = conn.cursor()
    cur.execute("""INSERT INTO messages(sender, subject, body_hash_hex, timestamp, nonce, aad_json, sig_hex)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (sender, subject, body_digest.hex(), ts, nonce, aad_json.decode(), signature.hex()))
    msg_id = cur.lastrowid

    for rname in recipients:
        _, r_cert_pem = get_user_material(conn, rname)
        r_cert = load_certificate(r_cert_pem)
        if r_cert.issuer != ca_cert.subject: raise ValueError(f"Cert de {rname} não emitido pela CA")
        enc_key = rsa_oaep_encrypt(r_cert.public_key(), aes_key)
        cur.execute("""INSERT INTO envelopes(msg_id, recipient, enc_key_b64, iv_b64, tag_b64, ciphertext_b64)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (msg_id, rname,
                     base64.b64encode(enc_key).decode(),
                     base64.b64encode(iv).decode(),
                     base64.b64encode(tag).decode(),
                     base64.b64encode(ciphertext).decode()))
    conn.commit()
    log_event(conn, "msg_send", {"id": msg_id, "from": sender, "to": recipients, "subject": subject})
    return msg_id

def list_inbox(conn: sqlite3.Connection, user: str):
    return conn.execute("""SELECT m.id, m.sender, m.subject, m.timestamp
                           FROM messages m JOIN envelopes e ON e.msg_id=m.id
                           WHERE e.recipient=? ORDER BY m.id DESC""",(user,)).fetchall()

def read_message(conn: sqlite3.Connection, user: str, msg_id: int):
    user_priv_pem, _ = get_user_material(conn, user)
    user_key = load_private_key(user_priv_pem)
    cur = conn.cursor()
    m = cur.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if not m: raise ValueError("Mensagem não encontrada")
    e = cur.execute("SELECT * FROM envelopes WHERE msg_id=? AND recipient=?", (msg_id, user)).fetchone()
    if not e: raise ValueError("Mensagem não endereçada a este usuário")

    aad_json = m["aad_json"].encode()
    iv = base64.b64decode(e["iv_b64"]); tag = base64.b64decode(e["tag_b64"])
    ciphertext = base64.b64decode(e["ciphertext_b64"])
    enc_key = base64.b64decode(e["enc_key_b64"])
    aes_key = rsa_oaep_decrypt(user_key, enc_key)
    plaintext = aes_gcm_decrypt(aes_key, iv, tag, ciphertext, aad_json)
    body = plaintext.decode()

    _, ca_cert_pem = ensure_ca(cur.connection)
    from_cert = load_certificate(cur.execute("SELECT cert_pem FROM users WHERE name=?", (m["sender"],)).fetchone()["cert_pem"])
    if from_cert.issuer != load_certificate(ca_cert_pem).subject:
        raise ValueError("Cert do remetente não encadeado")
    sig = bytes.fromhex(m["sig_hex"])
    ok_sig = rsa_pss_verify(from_cert.public_key(), sig, sha256(plaintext))

    nonce = json.loads(m["aad_json"])["nonce"]
    if not cur.execute("SELECT 1 FROM nonces WHERE nonce=?", (nonce,)).fetchone():
        raise ValueError("Nonce ausente")
    meta = {"id": m["id"], "from": m["sender"], "subject": m["subject"], "timestamp": m["timestamp"],
            "nonce": nonce, "signature_valid": ok_sig}
    log_event(cur.connection, "msg_read", {"id": m["id"], "by": user})
    return meta, body
