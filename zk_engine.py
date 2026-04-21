import json
import base64
import os
import ipaddress
from scapy.all import rdpcap, IP, TCP, UDP
from pybloom_live import ScalableBloomFilter
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import eddsa
from Crypto.PublicKey import ECC
from argon2.low_level import hash_secret_raw, Type
from datetime import datetime, timedelta, timezone
import pickle

# Argon2id parameters
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 102400
ARGON2_PARALLELISM = 8
ARGON2_HASH_LEN = 32

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a password using Argon2id."""
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID
    )

def encrypt_data(key: bytes, plaintext: bytes) -> (bytes, bytes, bytes):
    """Encrypt data using AES-GCM."""
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Decrypt data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def parse_connections_scapy(pcap_path):
    packets = rdpcap(pcap_path)
    connections = set()

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if TCP in pkt:
                proto = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                proto = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            else:
                continue

            conn_str = f"{src_ip}:{src_port}->{dst_ip}:{dst_port} ({proto})"
            connections.add(conn_str)

    return connections

def build_privacy_preserving_proof(connections_list, selected_connection, password, save_path, expiration_days=None):
    print(f"DEBUG: === PROOF BUILDER CALLED ===")
    print(f"DEBUG: Received {len(connections_list)} connections to prove")
    print(f"DEBUG: First few connections received:")
    for i, conn in enumerate(connections_list[:3]):
        print(f"  {i + 1}: '{conn}'")
    if len(connections_list) > 3:
        print(f"DEBUG: Last few connections received:")
        for i, conn in enumerate(connections_list[-3:], len(connections_list) - 3):
            print(f"  {i + 1}: '{conn}'")

    # Use the provided connections list directly
    connections = connections_list

    # Create traditional Bloom filter with FULL connections (including payload)
    bf = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)
    hashed_connections = []

    print(f"DEBUG: Adding {len(connections)} connections to Bloom filter...")
    for i, conn in enumerate(connections):
        h = SHA256.new(conn.encode()).digest()
        bf.add(h)
        hashed_connections.append(h)

        if (i + 1) % 100 == 0:
            print(f"DEBUG: Added {i + 1} connections to Bloom filter...")

    print(f"DEBUG: ✅ All {len(connections)} connections added to Bloom filter")

    # Derive encryption key from password (existing code)
    salt = get_random_bytes(16)
    enc_key = derive_key_from_password(password, salt)

    # Hash selected connection (existing code)
    selected_hash = SHA256.new(selected_connection.encode()).digest()

    # Generate Ed25519 key pair (existing code)
    signing_key = ECC.generate(curve='Ed25519')
    verifying_key = signing_key.public_key()
    signer = eddsa.new(signing_key, 'rfc8032')
    signature = signer.sign(selected_hash)

    # Encrypt traditional Bloom filter bits
    bloom_bytes = base64.b64encode(pickle_bloom(bf))
    nonce, ciphertext, tag = encrypt_data(enc_key, bloom_bytes)

    # Build proof dictionary
    proof = {
        # Traditional bloom filter (encrypted)
        'bloom_filter': {
            'salt': base64.b64encode(salt).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
        },

        # ADD THIS NEW SECTION:
        'proof_metadata': {
            'scope': 'entire_pcap' if selected_connection == 'ENTIRE_PCAP_PROOF' else 'single_connection',
            'total_connections': len(connections)
        },

        # Signature components
        'selected_hash': base64.b64encode(selected_hash).decode(),
        'signature': base64.b64encode(signature).decode(),
        'verifying_key': verifying_key.export_key(format='DER').hex(),
    }

    # Encrypt generated timestamp
    generated_time = datetime.utcnow().isoformat() + 'Z'
    generated_encrypted = encrypt_data(enc_key, generated_time.encode())
    proof['generated'] = {
        'nonce': base64.b64encode(generated_encrypted[0]).decode(),
        'ciphertext': base64.b64encode(generated_encrypted[1]).decode(),
        'tag': base64.b64encode(generated_encrypted[2]).decode()
    }

    # CHANGE: Add encrypted expiration fields
    if expiration_days:
        expires_at = datetime.utcnow() + timedelta(days=int(expiration_days))

        # Encrypt the expiration values
        exp_days_encrypted = encrypt_data(enc_key, str(expiration_days).encode())
        exp_date_encrypted = encrypt_data(enc_key, (expires_at.isoformat() + 'Z').encode())

        proof['expiration_days'] = {
            'nonce': base64.b64encode(exp_days_encrypted[0]).decode(),
            'ciphertext': base64.b64encode(exp_days_encrypted[1]).decode(),
            'tag': base64.b64encode(exp_days_encrypted[2]).decode()
        }
        proof['expires_at'] = {
            'nonce': base64.b64encode(exp_date_encrypted[0]).decode(),
            'ciphertext': base64.b64encode(exp_date_encrypted[1]).decode(),
            'tag': base64.b64encode(exp_date_encrypted[2]).decode()
        }

    # Save proof to file
    with open(save_path, 'w') as f:
        json.dump(proof, f, indent=2)

    return proof


def verify_privacy_preserving_proof(proof, password, selected_connection, payload=None):
    print(f"DEBUG: === VERIFICATION DEBUG START ===")
    print(f"DEBUG: Verifying connection: '{selected_connection}'")
    if payload:
        print(f"DEBUG: With payload: '{payload}'")
    else:
        print("DEBUG: Payload not provided - checking basic connection only")

    # Get the stored selected connection hash for comparison
    stored_selected_hash = base64.b64decode(proof['selected_hash'])

    # For signature verification, determine what was originally signed
    if 'proof_metadata' in proof and proof['proof_metadata'].get('scope') == 'entire_pcap':
        print("DEBUG: This is an entire PCAP proof")
        signature_verification_string = "ENTIRE_PCAP_PROOF"
    else:
        print("DEBUG: This is a single connection proof")
        signature_verification_string = selected_connection

    computed_selected_hash = SHA256.new(signature_verification_string.encode()).digest()
    print(f"DEBUG: Signature verification string: '{signature_verification_string}'")
    print(f"DEBUG: Stored hash: {stored_selected_hash.hex()}")
    print(f"DEBUG: Computed hash: {computed_selected_hash.hex()}")
    print(f"DEBUG: Hashes match: {stored_selected_hash == computed_selected_hash}")

    # Check expiration first
    if 'expires_at' in proof:
        print("DEBUG: Checking expiration...")
        try:
            exp_nonce = base64.b64decode(proof['expires_at']['nonce'])
            exp_ciphertext = base64.b64decode(proof['expires_at']['ciphertext'])
            exp_tag = base64.b64decode(proof['expires_at']['tag'])

            salt = base64.b64decode(proof['bloom_filter']['salt'])
            dec_key = derive_key_from_password(password, salt)

            expires_at_bytes = decrypt_data(dec_key, exp_nonce, exp_ciphertext, exp_tag)
            expires_at = datetime.fromisoformat(expires_at_bytes.decode().replace('Z', '+00:00'))

            if datetime.now(timezone.utc) > expires_at:
                return False, f"Proof expired on {expires_at.strftime('%Y-%m-%d %H:%M UTC')}"
            print("DEBUG: Expiration check passed")
        except Exception as exp_error:
            print(f"DEBUG: Expiration check failed: {exp_error}")
            return False, "Failed to verify expiration (wrong password?)"

    # Decrypt Bloom filter
    print("DEBUG: === DECRYPTING BLOOM FILTER ===")
    try:
        salt = base64.b64decode(proof['bloom_filter']['salt'])
        dec_key = derive_key_from_password(password, salt)

        nonce = base64.b64decode(proof['bloom_filter']['nonce'])
        ciphertext = base64.b64decode(proof['bloom_filter']['ciphertext'])
        tag = base64.b64decode(proof['bloom_filter']['tag'])

        print(f"DEBUG: Salt: {salt.hex()}")
        print(f"DEBUG: Derived key: {dec_key.hex()}")
        print(f"DEBUG: Nonce: {nonce.hex()}")
        print(f"DEBUG: Tag: {tag.hex()}")
        print(f"DEBUG: Ciphertext length: {len(ciphertext)}")

        bloom_bytes = decrypt_data(dec_key, nonce, ciphertext, tag)
        print("DEBUG: Bloom filter decryption successful")

        bf = unpickle_bloom(base64.b64decode(bloom_bytes))
        print(f"DEBUG: Bloom filter unpickled successfully, type: {type(bf)}")

    except Exception as decrypt_error:
        print(f"DEBUG: Bloom filter decryption failed: {decrypt_error}")
        return False, f"Failed to decrypt proof (wrong password?): {str(decrypt_error)}"

    # FLEXIBLE VERIFICATION LOGIC WITH DETAILED DEBUG
    print(f"DEBUG: === BLOOM FILTER MEMBERSHIP TESTING ===")

    # Test various connection string formats to find what's actually stored
    test_formats = []

    if payload:
        # With payload - test multiple formats
        test_formats = [
            f"{selected_connection} | {payload}",  # Full format
            f"{selected_connection}",  # Basic format
            f"{selected_connection} | [No payload]",  # Default payload format
            f"{selected_connection} | ",  # Empty payload
        ]
        print(f"DEBUG: Testing with payload: '{payload}'")
    else:
        # Without payload - test basic and common payload formats
        test_formats = [
            f"{selected_connection}",  # Basic format
            f"{selected_connection} | [No payload]",  # Default payload format
            f"{selected_connection} | ",  # Empty payload
        ]
        print("DEBUG: Testing without payload")

    # Add some variations for common formatting differences
    # Handle potential port format issues
    parts = selected_connection.split()
    if len(parts) >= 2:
        connection_part = parts[0]  # "IP:Port->IP:Port"
        protocol_part = " ".join(parts[1:])  # "(Protocol)"

        # Try with empty ports if they might be missing
        if "->" in connection_part:
            src_part, dst_part = connection_part.split("->")
            if ":" in src_part and ":" in dst_part:
                src_ip, src_port = src_part.split(":", 1)
                dst_ip, dst_port = dst_part.split(":", 1)

                # Add variations with different port formats
                test_formats.extend([
                    f"{src_ip}:->{dst_ip}: {protocol_part}",  # Empty ports
                    f"{src_ip}:None->{dst_ip}:None {protocol_part}",  # None ports
                    f"{src_ip}:{src_port}->{dst_ip}:{dst_port} {protocol_part} | [No payload]",  # Extra space
                ])

    print(f"DEBUG: Testing {len(test_formats)} different connection formats:")

    found_format = None
    for i, test_format in enumerate(test_formats):
        test_hash = SHA256.new(test_format.encode()).digest()
        is_in_bloom = test_hash in bf
        print(f"DEBUG: Test {i + 1}: '{test_format}'")
        print(f"  Hash: {test_hash.hex()}")
        print(f"  Found: {is_in_bloom}")

        if is_in_bloom and not found_format:
            found_format = test_format
            print(f"  ✅ MATCH FOUND!")

    # Determine verification result based on what we found
    if found_format:
        if payload:
            if f"| {payload}" in found_format:
                verification_result = (True, "Connection and payload verified.")
                print("DEBUG: ✅ Full connection with matching payload found")
            else:
                verification_result = (True, "Connection exists but payload doesn't match.")
                print("DEBUG: ✅ Connection found but payload mismatch")
        else:
            verification_result = (True, "Connection exists (payload not checked).")
            print("DEBUG: ✅ Basic connection found")
    else:
        verification_result = (False, "Connection not found.")
        print("DEBUG: ❌ No matching connection format found")

    print(f"DEBUG: Final verification result: {verification_result}")

    # Verify signature (always use the signature verification string)
    print(f"DEBUG: === SIGNATURE VERIFICATION ===")
    try:
        signature_hash = SHA256.new(signature_verification_string.encode()).digest()
        print(f"DEBUG: Signature hash: {signature_hash.hex()}")

        verifying_key_der = bytes.fromhex(proof['verifying_key'])
        verifying_key = ECC.import_key(verifying_key_der)

        verifier = eddsa.new(verifying_key, 'rfc8032')
        signature = base64.b64decode(proof['signature'])

        verifier.verify(signature_hash, signature)
        print("DEBUG: ✅ Signature verification passed")
    except ValueError as sig_error:
        print(f"DEBUG: ❌ Signature verification failed: {sig_error}")
        return False, "Invalid signature!"
    except Exception as sig_error:
        print(f"DEBUG: ❌ Signature verification error: {sig_error}")
        return False, f"Signature verification failed: {str(sig_error)}"

    print(f"DEBUG: === VERIFICATION DEBUG END ===")
    return verification_result

def pickle_bloom(bf):
    """Serialize Bloom filter to bytes."""
    return pickle.dumps(bf)

def unpickle_bloom(data):
    """Deserialize Bloom filter from bytes."""
    return pickle.loads(data)
