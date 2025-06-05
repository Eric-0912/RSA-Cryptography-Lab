from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_keys():
    """生成RSA密钥对"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def encrypt_message(public_key, message):
    """使用公钥加密消息"""
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_message(private_key, encrypted_msg):
    """使用私钥解密消息"""
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    decrypted = cipher.decrypt(base64.b64decode(encrypted_msg))
    return decrypted.decode()

if __name__ == "__main__":
    # 生成密钥
    public_key, private_key = generate_keys()
    
    # 要加密的消息
    message = "Hello"
    print(f"原始消息: {message}")
    
    # 加密
    encrypted = encrypt_message(public_key, message)
    print(f"加密后的消息 (Base64): {encrypted}")
    
    # 解密
    decrypted = decrypt_message(private_key, encrypted)
    print(f"解密后的消息: {decrypted}")
