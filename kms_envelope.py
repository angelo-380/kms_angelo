import os, json, base64
import boto3
from cryptography.fernet import Fernet

# 1. AWS KMS Client configuration
# Replace with your actual KMS Key ID, ARN, or Alias
KMS_KEY_ID = os.getenv("AWS_KMS_KEY_ID", "alias/my-kms-key")
kms = boto3.client("kms", region_name="us-east-1")

def encrypt_envelope(message: str, key_id: str) -> str:
    # 2. Request a 256-bit data key from KMS (returns plaintext key and encrypted key)
    response = kms.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    plaintext_data_key = base64.urlsafe_b64encode(response["Plaintext"])
    encrypted_data_key = response["CiphertextBlob"]

    # 3. Encrypt the message locally using the plaintext data key
    cipher = Fernet(plaintext_data_key)
    encrypted_message = cipher.encrypt(message.encode())

    # 4. Destroy the plaintext data key from memory immediately
    del plaintext_data_key

    # 5. Build and return the digital envelope (encrypted message + encrypted key)
    envelope = {
        "encrypted_message": base64.b64encode(encrypted_message).decode(),
        "encrypted_key": base64.b64encode(encrypted_data_key).decode()
    }
    return json.dumps(envelope)

def decrypt_envelope(envelope_json: str) -> tuple[str, str]:
    # 6. Parse the envelope
    envelope = json.loads(envelope_json)
    encrypted_key = base64.b64decode(envelope["encrypted_key"])
    encrypted_message = base64.b64decode(envelope["encrypted_message"])

    # 7. Ask KMS to decrypt the data key
    kms_response = kms.decrypt(CiphertextBlob=encrypted_key)
    restored_data_key = base64.urlsafe_b64encode(kms_response["Plaintext"])

    # 8. Decrypt the original message using the restored data key
    cipher = Fernet(restored_data_key)
    original_message = cipher.decrypt(encrypted_message).decode()

    # Return both the original message and the restored data key
    return original_message, restored_data_key.decode()

if __name__ == "__main__":
    sample_message = "Confidential test message for cloud security exam"
    print(f"[ORIGINAL]: {sample_message}")

    # Create envelope
    digital_envelope = encrypt_envelope(sample_message, KMS_KEY_ID)
    print(f"\n[DIGITAL ENVELOPE CREATED]:\n{digital_envelope}\n")

    # Decrypt envelope
    decrypted_msg, restored_key = decrypt_envelope(digital_envelope)
    print(f"[DECRYPTED] Message: {decrypted_msg}")
    print(f"[DECRYPTED] Restored Key: {restored_key}")
