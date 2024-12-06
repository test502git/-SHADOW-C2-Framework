from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import base64
import json

class CryptoHandler:
    def __init__(self):
        # 使用固定密钥（在实际应用中应该使用动态密钥）
        self.key = b'635ab6f704d54372' # 16字节AES密钥
        self.hmac_key = b'cb9de4ae4ff025d66f2d627e8cb08ce7' # HMAC密钥

    def encrypt(self, data):
        """
        加密数据
        1. 生成随机IV
        2. 使用AES-CBC加密
        3. 添加HMAC用于完整性验证
        """
        try:
            # 生成随机IV
            iv = get_random_bytes(16)
            
            # 创建AES加密器
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            
            # 填充数据
            data = data.encode()
            length = 16 - (len(data) % 16)
            data += bytes([length]) * length
            
            # 加密
            ciphertext = cipher.encrypt(data)
            
            # 组合IV和密文
            encrypted_data = iv + ciphertext
            
            # 计算HMAC
            h = HMAC.new(self.hmac_key, digestmod=SHA256)
            h.update(encrypted_data)
            
            # 组合最终数据: encrypted_data + hmac
            final_data = encrypted_data + h.digest()
            
            # Base64编码
            return base64.b64encode(final_data).decode()
            
        except Exception as e:
            raise Exception(f"加密错误: {str(e)}")

    def decrypt(self, data):
        """
        解密数据
        1. 验证HMAC
        2. 提取IV
        3. AES-CBC解密
        """
        try:
            # Base64解码
            data = base64.b64decode(data)
            
            # 分离HMAC
            hmac = data[-32:]  # SHA256 produces 32 bytes
            data = data[:-32]
            
            # 验证HMAC
            h = HMAC.new(self.hmac_key, digestmod=SHA256)
            h.update(data)
            try:
                h.verify(hmac)
            except:
                raise Exception("HMAC验证失败")
            
            # 提取IV
            iv = data[:16]
            ciphertext = data[16:]
            
            # 解密
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            # 去除填充
            padding_length = decrypted[-1]
            decrypted = decrypted[:-padding_length]
            
            return decrypted.decode()
            
        except Exception as e:
            raise Exception(f"解密错误: {str(e)}") 