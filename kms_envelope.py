import base64
import boto3
from cryptography.fernet import Fernet

KMS_KEY_ID = "e82c4d03-905e-47f4-a09e-fe9f5babcd7e"
REGION_NAME = "us-east-1"

kms_client = boto3.client("kms", region_name=REGION_NAME)


def encrypt_envelope(plaintext: str, key_id: str) -> dict:
    #Generates a data key via KMS and encrypts data locally
    response = kms_client.generate_data_key(KeyId=key_id, KeySpec="AES_256")
    fernet_key = base64.urlsafe_b64encode(response["Plaintext"][:32])

    ciphertext = Fernet(fernet_key).encrypt(plaintext.encode())

    return {
        "ciphertext": ciphertext,
        "encrypted_data_key": response["CiphertextBlob"],
    }


def decrypt_envelope(envelope: dict) -> str:
    #Decrypts the data key via KMS and recovers the original plaintext
    response = kms_client.decrypt(CiphertextBlob=envelope["encrypted_data_key"])
    fernet_key = base64.urlsafe_b64encode(response["Plaintext"][:32])

    return Fernet(fernet_key).decrypt(envelope["ciphertext"]).decode()


if __name__ == "__main__":
    message = "KMS text message"
    print(f"[ORIGINAL]: {message}")

    envelope = encrypt_envelope(message, KMS_KEY_ID)
    print(f"[ENCRYPTED]: {envelope['ciphertext'][:30]}...")

    recovered = decrypt_envelope(envelope)
    print(f"[RECOVERED]: {recovered}")
