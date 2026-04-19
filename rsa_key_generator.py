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
import secrets


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
        a = secrets.randbelow(n - 3) + 2  # 生成 2 到 n-2 之间的随机数
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


# 小素数表，用于快速筛选 - 扩展到10000以内的素数，提高4096位素数生成速度
SMALL_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291, 8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973]

def generate_prime(bits):
    """
    生成指定位数的素数
    使用小素数筛选优化，大幅提高生成速度
    使用 secrets 模块生成密码学安全的随机数
    
    Args:
        bits: 素数的位数
        
    Returns:
        int: 生成的素数
    """
    # 预计算小素数的乘积，用于快速筛选
    small_prime_product = 1
    for p in SMALL_PRIMES[:200]:  # 扩展到前200个小素数，提高4096位素数生成速度
        small_prime_product *= p
    
    attempts = 0
    while True:
        attempts += 1
        if attempts % 100 == 0:
            print(f"  已尝试 {attempts} 次...")
        
        # 生成一个密码学安全的随机数
        p = secrets.randbits(bits)
        # 确保p是奇数且高位为1
        p |= (1 << (bits - 1)) | 1
        
        # 快速筛选：检查是否能被小素数整除
        is_divisible = False
        for prime in SMALL_PRIMES:
            if p % prime == 0:
                is_divisible = True
                break
        
        if is_divisible:
            continue
        
        # 检测是否为素数（减少检测轮数以提高速度）
        if is_prime(p, k=40):  # 40轮检测足够安全
            print(f"  找到素数（尝试 {attempts} 次）")
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