import base64
import boto3
from cryptography.fernet import Fernet

KMS_KEY_ID = "e82c4d03-905e-47f4-a09e-fe9f5babcd7e"
kms_client = boto3.client("kms", region_name="us-east-1")


def encrypt_envelope(message: str, key_id: str) -> dict:
    # Generate plaintext data key and encrypted data key via KMS
    res = kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    raw_key = res["Plaintext"]

    # Encrypt the message locally using Fernet (AES-128-CBC + HMAC)
    fernet_key = base64.urlsafe_b64encode(raw_key[:32])
    ciphertext = Fernet(fernet_key).encrypt(message.encode())

    # Destroy the plaintext key from memory
    del raw_key
    del fernet_key

    # Return digital envelope containing ciphertext and encrypted data key
    return {
        "ciphertext": ciphertext,
        "encrypted_data_key": res["CiphertextBlob"],
    }


def decrypt_envelope(envelope: dict) -> tuple:
    # Decrypt data key using KMS Master Key
    res = kms_client.decrypt(CiphertextBlob=envelope["encrypted_data_key"])
    raw_key = res["Plaintext"]

    # Decrypt the message locally
    fernet_key = base64.urlsafe_b64encode(raw_key[:32])
    decrypted_message = Fernet(fernet_key).decrypt(envelope["ciphertext"]).decode()

    # Return recovered message and decrypted data key in hex format
    return decrypted_message, raw_key.hex()


if __name__ == "__main__":
    msg = "KMS test text message"
    print(f"[ORIGINAL]: {msg}")

    envelope = encrypt_envelope(msg, KMS_KEY_ID)
    print(f"[ENCRYPTED]: {envelope['ciphertext'][:30]}...")

    recovered_msg, recovered_key = decrypt_envelope(envelope)
    print(f"[RECOVERED MSG]: {recovered_msg}")
    print(f"[RECOVERED KEY (HEX)]: {recovered_key[:32]}...")
