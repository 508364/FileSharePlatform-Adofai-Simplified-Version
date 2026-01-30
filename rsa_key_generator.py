#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RSA密钥生成器

该脚本用于生成RSA密钥对（公钥和私钥），并以PEM格式保存到文件中。
不使用任何第三方库，完全基于Python标准库实现。
"""

import os
import random
import math
import sys


def is_prime(n, k=64):
    """
    使用Miller-Rabin算法检测一个数是否为素数
    
    Args:
        n: 要检测的数
        k: 检测轮数，轮数越多准确率越高
        
    Returns:
        bool: 如果n是素数返回True，否则返回False
    """
    # 处理小素数情况
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False
    
    # 把n-1分解为d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    # 进行k轮检测
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bits):
    """
    生成指定位数的素数
    
    Args:
        bits: 素数的位数
        
    Returns:
        int: 生成的素数
    """
    while True:
        # 生成一个随机数
        p = random.getrandbits(bits)
        # 确保p是奇数且高位为1
        p |= (1 << (bits - 1)) | 1
        # 检测是否为素数
        if is_prime(p):
            return p


def extended_gcd(a, b):
    """
    扩展欧几里得算法，用于计算模逆元
    使用迭代实现，避免递归深度限制
    
    Args:
        a: 第一个数
        b: 第二个数
        
    Returns:
        tuple: (gcd, x, y)，满足ax + by = gcd
    """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(a, m):
    """
    计算模逆元，即找到x使得(a * x) % m == 1
    
    Args:
        a: 要计算逆元的数
        m: 模数
        
    Returns:
        int: 模逆元
        
    Raises:
        ValueError: 如果逆元不存在
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"逆元不存在，gcd({a}, {m}) = {g}")
    else:
        return x % m


def generate_rsa_keys(bits=4096):
    """
    生成RSA密钥对
    
    Args:
        bits: 密钥的位数，默认为4096位
        
    Returns:
        tuple: (public_key, private_key)
            public_key: (e, n)
            private_key: (d, n)
    """
    print(f"正在生成RSA密钥对...")
    
    # 生成两个大素数p和q
    print("正在生成素数p...")
    p = generate_prime(bits // 2)
    print("正在生成素数q...")
    q = generate_prime(bits // 2)
    
    # 计算n = p * q
    n = p * q
    
    # 计算欧拉函数φ(n) = (p-1) * (q-1)
    phi = (p - 1) * (q - 1)
    
    # 选择公钥指数e，通常选择65537
    e = 65537
    
    # 计算私钥指数d，使得d ≡ e^-1 mod φ(n)
    print("正在计算私钥指数d...")
    d = mod_inverse(e, phi)
    
    # 返回密钥对
    public_key = (e, n)
    private_key = (d, n, p, q)
    
    print("RSA密钥对生成完成！")
    return public_key, private_key


def int_to_bytes(x):
    """
    将整数转换为字节串
    
    Args:
        x: 要转换的整数
        
    Returns:
        bytes: 转换后的字节串
    """
    # 确保0返回至少一个字节
    if x == 0:
        return b'\x00'
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')


def bytes_to_int(b):
    """
    将字节串转换为整数
    
    Args:
        b: 要转换的字节串
        
    Returns:
        int: 转换后的整数
    """
    return int.from_bytes(b, byteorder='big')


def encode_rsa_key(key, is_private):
    """
    将RSA密钥编码为PEM格式
    
    Args:
        key: 密钥元组
        is_private: 是否为私钥
        
    Returns:
        str: PEM格式的密钥字符串
    """
    import base64
    
    if is_private:
        d, n, p, q = key
        # 计算其他参数
        e = 65537  # 默认公钥指数
        dmp1 = d % (p - 1)
        dmq1 = d % (q - 1)
        iqmp = mod_inverse(q, p)
        
        # 构造ASN.1 DER编码的私钥
        # 简化实现，只处理基本情况
        
        # 使用PKCS#1格式
        # 私钥结构: RSAPrivateKey ::= SEQUENCE {
        #     version           Version,
        #     modulus           INTEGER,
        #     publicExponent    INTEGER,
        #     privateExponent   INTEGER,
        #     prime1            INTEGER,
        #     prime2            INTEGER,
        #     exponent1         INTEGER,
        #     exponent2         INTEGER,
        #     coefficient       INTEGER
        # }
        
        # 编码各个整数
        def encode_integer(i):
            b = int_to_bytes(i)
            # 如果最高位为1，需要添加一个0字节
            if b[0] & 0x80:
                b = b'\x00' + b
            
            # 计算长度
            length = len(b)
            
            # 处理长度编码
            if length < 128:
                # 短长度编码：一个字节，最高位为0
                length_bytes = bytes([length])
            else:
                # 长长度编码：第一个字节的最高位为1，表示后面有多少个字节表示长度
                length_bytes = bytes([(length.bit_length() + 7) // 8 + 0x80])
                length_bytes += length.to_bytes((length.bit_length() + 7) // 8, byteorder='big')
            
            return b'\x02' + length_bytes + b
        
        version = encode_integer(0)
        modulus = encode_integer(n)
        public_exponent = encode_integer(e)
        private_exponent = encode_integer(d)
        prime1 = encode_integer(p)
        prime2 = encode_integer(q)
        exponent1 = encode_integer(dmp1)
        exponent2 = encode_integer(dmq1)
        coefficient = encode_integer(iqmp)
        
        # 组合所有部分
        elements = [version, modulus, public_exponent, private_exponent, prime1, prime2, exponent1, exponent2, coefficient]
        sequence = b''.join(elements)
        
        # 处理序列长度编码
        sequence_length = len(sequence)
        if sequence_length < 128:
            # 短长度编码：一个字节，最高位为0
            sequence_length_bytes = bytes([sequence_length])
        else:
            # 长长度编码：第一个字节的最高位为1，表示后面有多少个字节表示长度
            length_bytes_count = (sequence_length.bit_length() + 7) // 8
            sequence_length_bytes = bytes([length_bytes_count + 0x80])
            sequence_length_bytes += sequence_length.to_bytes(length_bytes_count, byteorder='big')
        
        sequence = b'\x30' + sequence_length_bytes + sequence
        
        # 编码为PEM格式
        b64_data = base64.b64encode(sequence)
        b64_str = b64_data.decode('ascii')
        
        # 添加换行符，每64个字符换行
        pem_lines = [b64_str[i:i+64] for i in range(0, len(b64_str), 64)]
        pem_content = '-----BEGIN RSA PRIVATE KEY-----\n' + '\n'.join(pem_lines) + '\n-----END RSA PRIVATE KEY-----'
    else:
        e, n = key
        
        # 使用PKCS#1格式
        # 公钥结构: RSAPublicKey ::= SEQUENCE {
        #     modulus           INTEGER,
        #     publicExponent    INTEGER
        # }
        
        # 编码各个整数
        def encode_integer(i):
            b = int_to_bytes(i)
            # 如果最高位为1，需要添加一个0字节
            if b[0] & 0x80:
                b = b'\x00' + b
            
            # 计算长度
            length = len(b)
            
            # 处理长度编码
            if length < 128:
                # 短长度编码：一个字节，最高位为0
                length_bytes = bytes([length])
            else:
                # 长长度编码：第一个字节的最高位为1，表示后面有多少个字节表示长度
                length_bytes = bytes([(length.bit_length() + 7) // 8 + 0x80])
                length_bytes += length.to_bytes((length.bit_length() + 7) // 8, byteorder='big')
            
            return b'\x02' + length_bytes + b
        
        modulus = encode_integer(n)
        public_exponent = encode_integer(e)
        
        # 组合所有部分
        elements = [modulus, public_exponent]
        sequence = b''.join(elements)
        
        # 处理序列长度编码
        sequence_length = len(sequence)
        if sequence_length < 128:
            # 短长度编码：一个字节，最高位为0
            sequence_length_bytes = bytes([sequence_length])
        else:
            # 长长度编码：第一个字节的最高位为1，表示后面有多少个字节表示长度
            length_bytes_count = (sequence_length.bit_length() + 7) // 8
            sequence_length_bytes = bytes([length_bytes_count + 0x80])
            sequence_length_bytes += sequence_length.to_bytes(length_bytes_count, byteorder='big')
        
        sequence = b'\x30' + sequence_length_bytes + sequence
        
        # 编码为PEM格式
        b64_data = base64.b64encode(sequence)
        b64_str = b64_data.decode('ascii')
        
        # 添加换行符，每64个字符换行
        pem_lines = [b64_str[i:i+64] for i in range(0, len(b64_str), 64)]
        pem_content = '-----BEGIN RSA PUBLIC KEY-----\n' + '\n'.join(pem_lines) + '\n-----END RSA PUBLIC KEY-----'
    
    return pem_content


def save_rsa_keys(public_key, private_key, key_dir):
    """
    保存RSA密钥对到文件
    
    Args:
        public_key: 公钥
        private_key: 私钥
        key_dir: 保存密钥的目录
    """
    # 确保密钥目录存在
    os.makedirs(key_dir, exist_ok=True)
    
    # 生成PEM格式的密钥
    public_pem = encode_rsa_key(public_key, is_private=False)
    private_pem = encode_rsa_key(private_key, is_private=True)
    
    # 保存公钥到key.pem文件
    public_key_path = os.path.join(key_dir, 'key.pem')
    with open(public_key_path, 'w') as f:
        f.write(public_pem)
    print(f"公钥已保存到: {public_key_path}")
    
    # 保存私钥到private_key.pem文件
    private_key_path = os.path.join(key_dir, 'private_key.pem')
    with open(private_key_path, 'w') as f:
        f.write(private_pem)
    print(f"私钥已保存到: {private_key_path}")
    
    # 保存私钥到private_key.key文件（供用户下载）
    private_key_download_path = os.path.join(key_dir, 'private_key.key')
    with open(private_key_download_path, 'w') as f:
        f.write(private_pem)
    print(f"私钥下载文件已保存到: {private_key_download_path}")


def main():
    """
    主函数，生成并保存RSA密钥对
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='生成RSA密钥对')
    parser.add_argument('--bits', type=int, default=4096, help='密钥位数，默认为4096位')
    parser.add_argument('--output-dir', type=str, default='key', help='密钥保存目录，默认为key目录')
    
    args = parser.parse_args()
    
    # 生成RSA密钥对
    public_key, private_key = generate_rsa_keys(args.bits)
    
    # 保存密钥对
    save_rsa_keys(public_key, private_key, args.output_dir)
    
    print("\nRSA密钥对生成完成！")
    print("请妥善保管私钥文件，它是管理员身份的唯一凭证。")
    print("公钥文件将用于服务器验证管理员身份。")


if __name__ == "__main__":
    main()