#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件共享平台服务器端主程序

该程序实现了一个基于Flask的文件共享平台,提供文件上传、下载、管理功能,
以及系统资源监控、GitHub仓库克隆等辅助功能。
"""

# ==============================================
# 标准库导入
# ==============================================
import os
import sys
import shutil
import time
import json
import functools
import psutil
import socket
import netifaces
import threading
import requests
import queue
import hashlib
import tempfile
import zipfile
from datetime import datetime, timedelta
import re
import hmac
import random
import string
import uuid
import pickle
from collections import defaultdict


# ==============================================
# 第三方库导入
# ==============================================
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from flask import Flask, render_template, send_from_directory, send_file, request, jsonify, abort, session, redirect, url_for, flash, Response


# ==============================================
# 全局变量与配置
# ==============================================

# 运行初始化脚本
import init_app
import os
import sys

# 获取程序的基础路径，处理PyInstaller打包后的情况
def get_base_path():
    """获取程序的基础路径，处理PyInstaller打包后的情况"""
    if getattr(sys, 'frozen', False):
        # 如果是PyInstaller打包后的可执行文件
        base_path = os.path.dirname(sys.executable)
    else:
        # 否则使用当前脚本所在目录
        base_path = os.path.dirname(os.path.abspath(__file__))
    return base_path

# 初始化应用
init_app.main()

app = Flask(__name__)
# 重置Flask配置，使用最基本的配置确保session正常工作
# 使用固定secret_key确保会话一致性

# Token配置
TOKEN_FILE = os.path.join(get_base_path(), 'tokens.pkl')  # Token存储文件
TOKEN_EXPIRY = 3600  # Token有效期为1小时（3600秒）
TOKEN_LENGTH = 15    # Token长度为15位

# Token存储，使用字典保存token信息：{token: {'username': username, 'expiry': expiry_time}}
tokens = {}

# 清理过期token
def cleanup_expired_tokens():
    """定期清理过期的token"""
    global tokens
    current_time = time.time()
    expired_tokens = [token for token, info in tokens.items() if current_time >= info['expiry']]
    for token in expired_tokens:
        del tokens[token]
    # 保存到文件
    save_tokens()

# 保存tokens到pkl文件
def save_tokens():
    """保存tokens到pkl文件"""
    try:
        with open(TOKEN_FILE, 'wb') as f:
            pickle.dump(tokens, f)
    except Exception as e:
        print(f"保存tokens失败: {e}")

# 加载tokens从pkl文件
def load_tokens():
    """从pkl文件加载tokens"""
    global tokens
    try:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, 'rb') as f:
                tokens = pickle.load(f)
            # 清理过期token
            cleanup_expired_tokens()
    except Exception as e:
        print(f"加载tokens失败: {e}")
        tokens = {}

# 加载tokens
load_tokens()

# 生成15位由数字和大写字母组成的随机token
def generate_token():
    """生成15位随机token，包含数字和大写字母"""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(TOKEN_LENGTH))

# 检查token是否有效
def is_token_valid(token):
    """检查token是否有效且未过期"""
    if token not in tokens:
        return False
    
    token_info = tokens[token]
    current_time = time.time()
    return current_time < token_info['expiry']

# 获取token对应的用户名
def get_username_from_token(token):
    """根据token获取用户名"""
    if is_token_valid(token):
        return tokens[token]['username']
    return None

# 更新token有效期
def refresh_token(token):
    """刷新token有效期"""
    if token in tokens:
        tokens[token]['expiry'] = time.time() + TOKEN_EXPIRY
        save_tokens()  # 保存到文件
        return True
    return False

# 清理过期token
def cleanup_expired_tokens():
    """定期清理过期的token"""
    global tokens
    current_time = time.time()
    expired_tokens = [token for token, info in tokens.items() if current_time >= info['expiry']]
    for token in expired_tokens:
        del tokens[token]
    # 保存到文件
    save_tokens()

# 读取文件扩展名配置
def get_file_extension_config():
    """读取文件扩展名配置"""
    config_path = os.path.join('list', 'file_extensions.json')
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
            return config
    except Exception as e:
        app.logger.error(f"读取文件扩展名配置失败: {e}")
        # 返回默认配置
        return {
            "服务异常": "读取“文件扩展名”配置文件失败"
        }

# 保存文件扩展名配置
def save_file_extension_config(config):
    """保存文件扩展名配置"""
    config_path = os.path.join('list', 'file_extensions.json')
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        app.logger.error(f"保存文件扩展名配置失败: {e}")
        return False

# 检查文件扩展名是否允许上传
def is_file_extension_allowed(filename):
    """检查文件扩展名是否允许上传"""
    config = get_file_extension_config()
    
    if not config['enabled']:
        # 如果黑白名单功能未启用，允许所有文件上传
        return True
    
    # 获取文件扩展名
    ext = os.path.splitext(filename.lower())[1]
    
    if config['mode'] == 'whitelist':
        # 白名单模式：只允许配置中的扩展名
        return ext in config['extensions']
    else:
        # 黑名单模式：不允许配置中的扩展名
        return ext not in config['extensions']

# 定期清理过期token的线程
def start_token_cleanup():
    """启动定期清理过期token的线程"""
    def cleanup_thread():
        while True:
            cleanup_expired_tokens()
            # 每30分钟清理一次
            time.sleep(1800)
    
    thread = threading.Thread(target=cleanup_thread, daemon=True)
    thread.start()

# 只设置必要的会话过期时间
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)


# 用户登录检查装饰器
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # 检查是否为管理员登录（优先检查，不受用户登录设置影响）
            if 'admin_token' in session:
                # 管理员已登录，直接允许访问
                app.logger.info(f"管理员已登录，直接允许访问受保护页面")
                return f(*args, **kwargs)
            
            # 检查是否有token验证
            token = request.headers.get('Authorization') or request.headers.get('X-Token')
            if token:
                # 移除Bearer前缀（如果存在）
                if token.startswith('Bearer '):
                    token = token[7:]
                # 检查token是否有效
                if is_token_valid(token):
                    # token有效，允许访问
                    app.logger.info(f"Token验证成功，继续访问受保护页面")
                    # 在session中设置用户名，以便后续使用
                    username = get_username_from_token(token)
                    session['user_logged_in'] = True
                    session['username'] = username
                    return f(*args, **kwargs)
                else:
                    app.logger.info(f"Token无效或已过期")
                    # 对于API请求，返回401状态码
                    if request.is_json or request.path.startswith('/api/'):
                        return jsonify({"status": "error", "message": "Token无效或已过期"}), 401
                    # 对于页面请求，重定向到登录页
                    return redirect(url_for('index'))
            
            # 检查是否启用用户登录
            if not system_config.get('user_login_enabled', False):
                # 未启用用户登录，自动创建游客会话
                if 'user_logged_in' not in session:
                    # 清空旧session
                    session.clear()
                    # 设置session为永久会话
                    session.permanent = True
                    # 设置登录标记和游客信息
                    session['user_logged_in'] = True
                    session['username'] = '游客'
                    session['login_time'] = datetime.now().isoformat()
                    # 记录详细日志
                    app.logger.info(f"用户登录功能已关闭，自动为游客创建会话")
                # 直接继续访问受保护页面
                return f(*args, **kwargs)
            
            # 检查session对象是否存在
            if session is None:
                app.logger.error("会话对象不存在，重定向到登录页")
                return redirect(url_for('index'))
            
            # 记录session状态以便调试
            session_keys = list(session.keys()) if session else []
            app.logger.info(f"访问受保护页面，session内容: {session_keys}")
            
            # 检查是否登录
            if 'user_logged_in' not in session:
                app.logger.info(f"会话验证失败: 'user_logged_in'不在session中，重定向到登录页")
                return redirect(url_for('index'))
            
            # 验证登录状态值
            if not session.get('user_logged_in', False):
                app.logger.info(f"会话验证失败: 'user_logged_in'值为False，重定向到登录页")
                return redirect(url_for('index'))
            
            # 检查session对应的token是否有效（新增）
            username = session.get('username')
            if username and username != '游客':
                # 查找该用户对应的token
                valid_token = False
                for token, info in tokens.items():
                    if info['username'] == username and is_token_valid(token):
                        valid_token = True
                        break
                
                if not valid_token:
                    app.logger.info(f"会话验证失败: 对应的Token无效或已被删除，重定向到登录页")
                    # 清除session
                    session.clear()
                    return redirect(url_for('index'))
            
            # 验证通过，继续处理
            app.logger.info(f"会话验证成功，继续访问受保护页面")
            return f(*args, **kwargs)
        except Exception as e:
            # 捕获所有可能的异常并记录
            app.logger.error(f"会话验证过程中发生错误: {str(e)}")
            return redirect(url_for('index'))
    return decorated_function

# 线程锁 - 用于确保文件操作的线程安全
upload_lock = threading.Lock()

# 系统配置默认值
DEFAULT_CONFIG = {
    'upload_folder': 'uploads',        # 文件上传目录
    'max_file_size': 100,              # 单个文件最大大小(MB)
    'max_total_size': 1024,            # 总存储空间大小(MB)
    'app_name': '文件共享平台-adofai特别版',         # 应用名称
    'app_version': 'v2.0',             # 应用版本
    'port': 5000,                      # 服务端口
    'network_interface': 'auto',       # 网络接口配置
    'user_login_enabled': True,        # 是否启用用户登录
    'secret_key': '',                  # 应用密钥，为空时会自动生成
}

# 系统当前配置 - 初始化为默认配置的副本
system_config = DEFAULT_CONFIG.copy()

# ============================================== 
# 主题设置功能 
# ===============================================
THEME_FILE = os.path.join(get_base_path(), 'theme_settings.json')  # 主题设置文件

# 默认主题颜色
DEFAULT_THEME_COLORS = {
    'primary': '#4A76FF',
    'secondary': '#6A5AF9',
    'success': '#1cc88a',
    'warning': '#f6c23e',
    'danger': '#e74a3b'
}

def get_theme_settings():
    """
    获取主题设置
    
    Returns:
        dict: 主题颜色设置
    """
    try:
        if os.path.exists(THEME_FILE):
            with open(THEME_FILE, 'r', encoding='utf-8') as f:
                colors = json.load(f)
            # 确保所有必需的颜色都存在
            for key, default_value in DEFAULT_THEME_COLORS.items():
                if key not in colors:
                    colors[key] = default_value
            return colors
        else:
            # 如果文件不存在，返回默认颜色并保存
            save_theme_settings(DEFAULT_THEME_COLORS)
            return DEFAULT_THEME_COLORS
    except Exception as e:
        print(f"加载主题设置失败: {e}")
        return DEFAULT_THEME_COLORS

def save_theme_settings(colors):
    """
    保存主题设置
    
    Args:
        colors (dict): 主题颜色设置
    """
    try:
        # 确保只保存有效的颜色设置
        valid_colors = {}
        for key, default_value in DEFAULT_THEME_COLORS.items():
            if key in colors and isinstance(colors[key], str):
                valid_colors[key] = colors[key]
            else:
                valid_colors[key] = default_value
        
        with open(THEME_FILE, 'w', encoding='utf-8') as f:
            json.dump(valid_colors, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"保存主题设置失败: {e}")

# ============================================== 
# 配置文件检查与更新功能 
# ===============================================

def check_for_updates(current_version):
    """
    检查GitHub上是否有新版本
    
    Args:
        current_version (str): 当前应用版本
    
    Returns:
        dict: 包含更新信息的字典,如果没有更新则返回None
    """
    try:
        # GitHub仓库信息
        owner = '508364'
        repo = 'FileSharePlatform-Adofai-Simplified-Version'
        api_url = f'https://api.github.com/repos/{owner}/{repo}/releases/latest'
        
        # 发送请求
        req_session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        req_session.mount('https://', adapter)
        
        response = req_session.get(api_url, timeout=10)
        response.raise_for_status()
        
        # 解析响应
        release_info = response.json()
        latest_tag = release_info.get('tag_name', '')
        
        # 提取版本号，移除可能的前缀
        latest_version = latest_tag.replace('FileSharePlatform-v', '').replace('v', '')
        current_version_clean = current_version.replace('v', '')
        
        # 版本比较 - 简单的数字比较
        def parse_version(v):
            try:
                parts = list(map(int, v.split('.')))
                while len(parts) < 3:  # 确保至少有3个部分
                    parts.append(0)
                return parts
            except ValueError:
                return [0, 0, 0]
        
        # 版本比较
        if latest_version and parse_version(latest_version) > parse_version(current_version_clean):
            # 构建下载链接
            download_url = f'https://github.com/{owner}/{repo}/releases/tag/{latest_tag}'
            
            return {
                'current_version': current_version,
                'latest_version': f'v{latest_version}',
                'download_url': download_url,
                'release_notes': release_info.get('body', '')
            }
        return None
    except Exception as e:
        print(f"检查更新失败: {e}")
        return None

# 配置与元数据文件路径
CONFIG_FILE = os.path.join(get_base_path(), 'fileshare_config.ini')   # 系统配置文件
METADATA_FILE = os.path.join(get_base_path(), 'files_metadata.json')   # 文件元数据存储文件

# 服务启动时间
SERVICE_START_TIME = datetime.now()

# ==============================================
# 系统初始化与配置管理
# ==============================================

def check_and_update_config_file():
    """
    检查并更新配置文件
    
    确保配置文件包含所有必需的配置项，并更新应用版本
    
    Returns:
        bool: 配置文件是否被更新
    """
    config_updated = False
    
    # 确保配置文件存在
    if not os.path.exists(CONFIG_FILE):
        save_config()
        print("配置文件不存在，已创建默认配置文件")
        return True
    
    try:
        # 读取当前配置文件
        with open(CONFIG_FILE, 'r', encoding='utf-8-sig') as f:
            current_config = json.load(f)
        
        # 创建一个新的配置字典，包含所有默认配置项
        new_config = DEFAULT_CONFIG.copy()
        
        # 更新新配置字典，保留现有的非默认配置值
        for key, value in current_config.items():
            if key == 'app_version':
                # 跳过版本号，确保版本号始终为最新（在new_config中已设置）
                continue
            elif key in new_config:
                new_config[key] = value
            else:
                print(f"发现未知配置项: {key}")
        
        # 检查配置是否有变化
        config_has_changes = False
        for key in new_config:
            # 跳过app_version，因为它是特殊处理的
            if key == 'app_version':
                continue
            if key not in current_config or new_config[key] != current_config.get(key):
                config_has_changes = True
                break
        
        # 如果配置有变化，保存新配置
        if config_has_changes:
            with open(CONFIG_FILE, 'w', encoding='utf-8-sig') as f:
                json.dump(new_config, f, indent=4, ensure_ascii=False)
            config_updated = True
            print("配置文件已更新")
            
            # 显示更新的配置项
            for key in new_config:
                # 跳过app_version，因为它是特殊处理的
                if key == 'app_version':
                    continue
                if key not in current_config:
                    print(f"  + 添加配置项: {key} = {new_config[key]}")
                elif new_config[key] != current_config[key]:
                    print(f"  ~ 更新配置项: {key} = {new_config[key]} (原: {current_config[key]})")
    except Exception as e:
        print(f"配置文件检查与更新失败: {e}")
        # 创建默认配置文件
        with open(CONFIG_FILE, 'w', encoding='utf-8-sig') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4, ensure_ascii=False)
        print("已创建默认配置文件")
        config_updated = True
    
    return config_updated

def init_system():
    """
    初始化系统环境
    
    创建必要目录、加载保存配置并确保元数据文件有效
    """
    
    # 获取基础路径，处理PyInstaller打包后的情况
    base_path = get_base_path()
    
    # 设置上传目录为绝对路径
    if not os.path.isabs(system_config['upload_folder']):
        # 如果upload_folder是相对路径，使用基础路径拼接
        system_config['upload_folder'] = os.path.join(base_path, system_config['upload_folder'])
    
    # 创建上传目录
    if not os.path.exists(system_config['upload_folder']):
        os.makedirs(system_config['upload_folder'])
    
    # 检查并更新配置文件
    config_updated = check_and_update_config_file()
    
    # 重新加载保存的配置
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8-sig') as f:
                saved_config = json.load(f)
                for key in saved_config:
                    if key in system_config:
                        system_config[key] = saved_config[key]
        except Exception as e:
            print(f"配置加载错误: {e}")
    else:
        # 首次启动时创建默认配置文件
        save_config()
    
    # 更新TOKEN_EXPIRY变量
    global TOKEN_EXPIRY
    if 'token_expiry' in system_config:
        TOKEN_EXPIRY = system_config['token_expiry']
    else:
        # 如果配置中没有token_expiry，使用默认值并保存到配置
        TOKEN_EXPIRY = 3600
        system_config['token_expiry'] = TOKEN_EXPIRY
        save_config()
    
    # 确保元数据文件有效
    if not os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'w', encoding='utf-8-sig') as f:
            json.dump({}, f)
    
    # 修复空文件问题
    elif os.path.getsize(METADATA_FILE) == 0:
        with open(METADATA_FILE, 'w', encoding='utf-8-sig') as f:
            json.dump({}, f)
    
    # 检查并生成RSA密钥
    key_dir = os.path.join(base_path, 'key')
    public_key_path = os.path.join(key_dir, 'key.pem')
    private_key_path = os.path.join(key_dir, 'private_key.pem')
    private_key_download_path = os.path.join(key_dir, 'private_key.key')
    
    # 如果密钥目录不存在，创建目录
    if not os.path.exists(key_dir):
        os.makedirs(key_dir)
    
    # 如果公钥不存在，生成新的RSA密钥对
    if not os.path.exists(public_key_path):
        print("首次启动，正在生成RSA密钥对...")
        
        # 直接导入rsa_key_generator模块生成密钥
        try:
            import rsa_key_generator
            # 生成RSA密钥对
            public_key, private_key = rsa_key_generator.generate_rsa_keys(bits=4096)
            # 保存密钥对
            rsa_key_generator.save_rsa_keys(public_key, private_key, key_dir)
            print("RSA密钥对生成完成！")
        except Exception as e:
            print(f"错误：生成RSA密钥对失败！{str(e)}")
    
    print("系统初始化完成,元数据文件已就绪")


def hash_password(password):
    """对密码进行哈希处理"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password, hashed_password):
    """验证密码是否匹配"""
    return hash_password(password) == hashed_password

def encrypt_password(password):
    """使用对称密钥加密密码"""
    # 使用用户提供的对称密钥
    key = b'ccfb9b1700#63d70009b6_36ce8721ae?4894900701\693b4b1ba6-5d51823868$083a803ff1}6b6f30c75a\3d43ec2bb7%2877b23160?eb20aa241b-578552ec50+60bfe13c'
    # 简单的XOR加密
    encrypted = ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(password))
    return encrypted.encode('utf-8').hex()

def decrypt_password(encrypted_password):
    """解密密码"""
    # 使用用户提供的对称密钥
    key = b'ccfb9b1700#63d70009b6_36ce8721ae?4894900701\693b4b1ba6-5d51823868$083a803ff1}6b6f30c75a\3d43ec2bb7%2877b23160?eb20aa241b-578552ec50+60bfe13c'
    # 解密
    encrypted_bytes = bytes.fromhex(encrypted_password)
    decrypted = ''.join(chr(b ^ key[i % len(key)]) for i, b in enumerate(encrypted_bytes))
    return decrypted

def verify_password_encrypted(password, encrypted_password):
    """验证加密密码是否匹配"""
    return password == decrypt_password(encrypted_password)


def update_user_files(username, filename, action='add'):
    """
    更新用户的文件列表
    
    Args:
        username (str): 用户名
        filename (str): 文件名
        action (str): 操作类型,可选值: 'add' | 'remove'
    
    Returns:
        bool: 更新是否成功
    """
    users_file = os.path.join('user', 'user.json')
    try:
        with open(users_file, 'r', encoding='utf-8') as f:
            user_data = json.load(f)
        
        for user in user_data['users']:
            if user['username'] == username:
                if action == 'add':
                    # 添加文件到用户的File列表
                    if filename not in user.get('File', []):
                        if 'File' not in user:
                            user['File'] = []
                        user['File'].append(filename)
                elif action == 'remove':
                    # 从用户的File列表中移除文件
                    if 'File' in user and filename in user['File']:
                        user['File'].remove(filename)
                break
        
        with open(users_file, 'w', encoding='utf-8') as f:
            json.dump(user_data, f, ensure_ascii=False, indent=4)
        
        return True
    except Exception as e:
        print(f"更新用户文件列表失败: {e}")
        return False


def save_config():
    """保存当前配置到配置文件"""
    try:
        # 创建配置副本以避免修改原始配置
        config_to_save = system_config.copy()
        
        # 删除可能存在的密码字段（不再使用密码验证机制）
        if 'admin_password' in config_to_save:
            del config_to_save['admin_password']
        if 'admin_user' in config_to_save:
            del config_to_save['admin_user']
        
        with open(CONFIG_FILE,'w', encoding='utf-8-sig') as f:  # 使用utf-8-sig编码保存
            json.dump(config_to_save,f,indent=4,ensure_ascii=False)
    except Exception as e:
        print(f"配置保存失败: {e}")

# ==============================================
# 文件元数据管理
# ==============================================

# 用于记录文件下载时间的字典，防止多线程下载时重复计数
# 格式: {filename: last_download_time}
download_time_records = {}
# 下载去重时间窗口（秒）
DOWNLOAD_DEDUPE_WINDOW = 1

def load_metadata():
    """
    加载文件元数据
    
    如果文件不存在或为空,创建有效的JSON文件;
    如果文件格式错误,尝试重置为有效JSON
    
    Returns:
        dict: 包含文件元数据的字典
    """
    # 如果文件不存在或为空,创建有效的JSON文件
    if not os.path.exists(METADATA_FILE) or os.path.getsize(METADATA_FILE) == 0:
        try:
            with open(METADATA_FILE, 'w', encoding='utf-8-sig') as f:
                json.dump({}, f)  # 创建有效的空JSON
            return {}
        except Exception as e:
            print(f"元数据文件创建失败:.{e}")
            return {}
    
    try:
        with open(METADATA_FILE, 'r', encoding='utf-8-sig') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print("元数据文件格式错误,重置中...")
        try:
            with open(METADATA_FILE, 'w', encoding='utf-8-sig') as f:
                json.dump({}, f)  # 重置为有效JSON
            return {}
        except Exception as e:
            print(f"元数据重置失败: {e}")
            return {}
    except Exception as e:
        print(f"元数据加载错误: {e}")
        return {}


def update_metadata(filename, action='upload', user=None):
    """
    更新文件元数据
    
    Args:
        filename (str): 文件名
        action (str): 操作类型,可选值: 'upload' | 'download' | 'delete'
        user (str): 上传用户的用户名
    
    Returns:
        dict or None: 更新后的文件元数据,如文件不存在则返回None
    """
    metadata = load_metadata()
    file_path = os.path.join(system_config['upload_folder'], filename)
    
    if not os.path.exists(file_path) and action != 'delete':
        return None
    
    # 获取文件属性
    if action != 'delete':
        stat = os.stat(file_path)
        file_size = stat.st_size
        file_mtime = stat.st_mtime
        file_ctime = stat.st_ctime
    
    # 初始化文件元数据
    if filename not in metadata and action != 'delete':
        metadata[filename] = {
            'size': file_size,
            'created': file_ctime,
            'modified': file_mtime,
            'download_count': 0,
            'user': user or 'unknown'
        }
    
    # 更新元数据
    if action == 'download':
        # 检查是否在去重时间窗口内
        current_time = time.time()
        last_download_time = download_time_records.get(filename, 0)
        
        # 如果不在时间窗口内，才增加下载次数
        if current_time - last_download_time > DOWNLOAD_DEDUPE_WINDOW:
            metadata[filename]['download_count'] += 1
            download_time_records[filename] = current_time
    elif action == 'upload':
        metadata[filename]['size'] = file_size
        metadata[filename]['modified'] = file_mtime
        
        # 如果是.adofai文件，解析并存储相关信息
        if filename.lower().endswith('.adofai'):
            adofai_info = parse_adofai_file(file_path)
            if adofai_info:
                metadata[filename]['adofai_info'] = adofai_info
    elif action == 'delete' and filename in metadata:  
        del metadata[filename]
        # 同时删除下载时间记录
        if filename in download_time_records:
            del download_time_records[filename]
    
    # 保存元数据
    try:
        with open(METADATA_FILE, 'w', encoding='utf-8-sig') as f:
            json.dump(metadata, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"元数据保存失败:.{e}")
    
    return metadata.get(filename) if action != 'delete' else None


def get_file_list():
    """
    获取上传目录中的文件列表
    
    Returns:
        list: 包含文件信息的字典列表,每个字典包含文件名、大小、修改时间等信息
    
    """
    upload_dir = system_config['upload_folder']
    if not os.path.exists(upload_dir):
        return []
    
    metadata = load_metadata()
    files = []
    
    for filename in os.listdir(upload_dir):  
        # 安全检查，防止目录遍历攻击
        if '../' in filename or not re.match(r'^[\w\-. \u4e00-\u9fa5]+$', filename):
            continue
        
        file_path = os.path.join(upload_dir, filename)
        if os.path.isfile(file_path):
            try:
                file_info = os.stat(file_path)
                file_meta = metadata.get(filename, {})
                
                file_item = {
                    'filename': filename,
                    'name': filename,
                    'size': file_info.st_size,
                    'filesize': file_info.st_size,
                    'modified': file_info.st_mtime,
                    'created': file_info.st_ctime,
                    'download_count': file_meta.get('download_count', 0)
                }
                
                # 如果是.adofai文件，添加解析信息
                if filename.lower().endswith('.adofai') and 'adofai_info' in file_meta:
                    file_item['adofai_info'] = file_meta['adofai_info']
                
                files.append(file_item)
            except Exception as e:
                print(f"获取文件信息失败: {filename}, 错误: {e}")
    
    # 按修改时间排序(最新在上)
    files.sort(key=lambda x: x['modified'], reverse=True)
    
    return files

# ==============================================
# 系统资源与磁盘使用
# ==============================================

def get_disk_usage():
    """
    获取磁盘空间使用情况
    
    Returns:
        dict: 包含系统磁盘和上传目录使用情况的字典
    """
    upload_dir = system_config['upload_folder']
    
    # 确保上传目录存在
    if not os.path.exists(upload_dir):  
        os.makedirs(upload_dir)
    
    # 计算上传目录使用空间
    upload_usage = 0
    for entry in os.scandir(upload_dir):
        if entry.is_file():
            upload_usage += entry.stat().st_size
    
    max_total_bytes = system_config['max_total_size'] * pow(1024, 2)  # MB转Bytes
    
    # 获取系统实际可用空间
    try:
        total, used, free = shutil.disk_usage("/")
        # 实际可用空间取系统可用空间和配置剩余空间的较小值
        available = min(free, max_total_bytes - upload_usage)  
    except:  
        # 回退方案
        available = max_total_bytes - upload_usage
    
    # 计算使用百分比
    usage_percent = 0
    if max_total_bytes > 0:
        usage_percent = min(100, int((upload_usage / max_total_bytes) * 100 ))
    
    return {  
        'system_total': total,
        'system_used': used,
        'system_free': free,
        'upload_total': max_total_bytes,
        'upload_used': upload_usage,
        'available': min(max_total_bytes - upload_usage, free),
        'usage_percent': usage_percent
    }


def get_system_resources():
    """
    获取系统资源信息(CPU、内存、网络接口)
    
    Returns:
        dict: 包含系统资源使用情况的字典
    """
    try:
        # CPU使用率
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # 内存使用率
        mem = psutil.virtual_memory()
        mem_percent = mem.percent
        mem_total = mem.total 
        mem_used = mem.used
        
        #网络接口 
        interfaces = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for link in addrs[netifaces.AF_INET]: 
                    interfaces.append({
                        'interface': iface, 
                        'ip': link['addr']
                    })
        
        return {
            'cpu_percent': cpu_percent,
            'mem_percent': mem_percent,
            'mem_total': mem_total,
            'mem_used': mem_used,
            'interfaces': interfaces
        }
    except Exception as e:
        print(f"获取系统资源失败: {e}")
        # 返回数据
        return { 
            'cpu_percent': '获取系统资源失败',
            'mem_percent': '获取系统资源失败',
            'mem_total': '获取系统资源失败',
            'mem_used': '获取系统资源失败',
            'interfaces': [
                {'interface': '本地连接', 'ip': '127.0.0.1'}
            ]
        }

# ===============================================
# 认证与安全
# ===============================================

def require_admin_token(func):
    """
    管理员认证装饰器
    
    检查请求是否包含有效的管理员令牌,用于保护需要管理员权限的接口
    对于Web界面访问，重定向到登录页面
    对于API访问，返回403错误
    当key文件夹为空时，允许直接访问admin页面
    
    Args:
        func:.需要保护的视图函数
    
    Returns:
        wrapper: 装饰后的函数
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        
        # 优先检查session
        if 'admin_token' in session:
            return func(*args, **kwargs)
            
        # 其次检查请求头
        token = request.headers.get('X-Admin-Token')
        if token and token == session.get('admin_token'):
            return func(*args, **kwargs)
        
        # 检查私钥文件是否存在
        try:
            base_path = get_base_path()
            private_key_path = os.path.join(base_path, 'key', 'private_key.key')
            private_key_pem_path = os.path.join(base_path, 'key', 'private_key.pem')
            
            # 如果私钥文件存在，允许直接访问
            if os.path.exists(private_key_path) or os.path.exists(private_key_pem_path):
                # 私钥文件存在，允许直接访问
                print("私钥文件存在，允许直接访问admin页面")
                # 生成一个临时admin_token，允许当前会话访问
                session['admin_token'] = os.urandom(32).hex()
                session['admin_username'] = 'admin'
                session.permanent = True
                return func(*args, **kwargs)
        except Exception as e:
            print(f"检查私钥文件时出错: {e}")
        
        # 判断是否为API请求（通过Accept头或URL路径判断）
        if request.headers.get('Accept') == 'application/json' or request.path.startswith('/api/'):
            return jsonify({"status": "error", "message": "未授权访问"}), 403
        
        # 对于Web界面访问，重定向到登录页面
        return redirect('/admin/login')
    
    return wrapper

# ===============================================
# Adofai文件解析功能
# ===============================================

def parse_adofai_file(file_path):
    """
    解析.adofai文件，提取歌曲信息、BPM、难度等属性
    
    Args:
        file_path (str): .adofai文件路径
    
    Returns:
        dict: 包含解析信息的字典
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 解析JSON内容
        data = json.loads(content)
        
        # 提取settings部分
        settings = data.get('settings', {})
        
        # 提取pathData并计算步数
        path_data = data.get('pathData', '')
        steps_count = len(path_data)
        
        # 提取关键信息
        song_info = {
            'song': settings.get('song', '未知'),
            'artist': settings.get('artist', '未知'),
            'author': settings.get('author', '未知'),
            'difficulty': settings.get('difficulty', '未知'),
            'bpm': settings.get('bpm', '未知'),
            'previewImage': settings.get('previewImage', '未知'),
            'previewIcon': settings.get('previewIcon', '未知'),
            'seizureWarning': settings.get('seizureWarning', False),
            'bg': settings.get('bg', '未知'),
            'song_filename': settings.get('songFilename', ''),
            'level_tags': settings.get('levelTags', ''),
            'actions_count': len(data.get('actions', [])),
            'steps_count': steps_count
        }
        
        return song_info
    except json.JSONDecodeError as e:
        print(f"解析.adofai文件JSON时出错: {e}")
        return None
    except Exception as e:
        print(f"解析.adofai文件时出错: {e}")
        return None


# ===============================================
# 实用工具函数
# ===============================================

def convert_size(size_bytes):
    """
    根据文件大小自动选择合适的单位
    
    Args:
        size_bytes (int/str): 字节数(支持整数或字符串类型的数值)
    
    Returns:
        str: 带单位的格式化大小字符串
    """
    # 添加类型转换和错误处理
    try:
        size_bytes = int(size_bytes)
    except (ValueError, TypeError):
        return "0B"  # 转换失败时返回默认值
    
    if size_bytes == 0:
        return "0B"
    units = ("B", "KB", "MB", "GB", "TB")
    i = 0
    size = size_bytes
    
    while size >= 1024 and i < len(units)-1:
        size /= 1024.0
        i += 1
    
    # 根据大小选择合适的精度
    if size < 10:
        return f"{size:.2f} {units[i]}"
    elif size < 100:
        return f"{size:.1f} {units[i]}"
    else:
        return f"{size:.0f} {units[i]}"

# ===============================================
# Flask路由定义
# ===============================================

# 管理员相关路由
@app.route('/admin/users', methods=['GET', 'POST'])
@require_admin_token
def admin_users():
    """管理员用户管理API - 使用username类和password类进行用户识别"""
    try:
        # GET请求 - 获取用户列表
        if request.method == 'GET':
            users = []
            users_file = os.path.join('user', 'user.json')
            if os.path.exists(users_file):
                with open(users_file, 'r', encoding='utf-8') as f:
                    user_data = json.load(f)
                    # 从users数组中提取用户信息，包括用户名和QQ
                    if 'users' in user_data:
                        for user in user_data['users']:
                            users.append({
                                'username': user.get('username'),
                                'qq': user.get('qq', '')
                            })
            return jsonify({'status': 'success', 'users': users})
        
        # POST请求 - 处理用户管理操作
        if request.method == 'POST':
            # 检查是否为JSON请求
            if not request.is_json:
                return jsonify({'status': 'error', 'message': '无效的请求格式'}), 400
        
        data = request.get_json()
        action = data.get('action')
        username_value = data.get('username')
        password_value = data.get('password')
        
        # 验证必要参数
        if not action or not username_value:
            return jsonify({'status': 'error', 'message': '缺少必要参数'}), 400
        
        # 读取现有用户数据
        users_file = os.path.join('user', 'user.json')
        user_data = {'users': []}
        if os.path.exists(users_file):
            with open(users_file, 'r', encoding='utf-8') as f:
                user_data = json.load(f)
                if 'users' not in user_data:
                    user_data['users'] = []
        
        users = user_data['users']
        
        # 执行相应操作
        if action == 'add':
            # 检查用户是否已存在
            for user in users:
                if user.get('username') == username_value:
                    return jsonify({'status': 'error', 'message': '用户名已存在'}), 400
            
            # 密码长度验证
            if len(password_value) < 6:
                return jsonify({'status': 'error', 'message': '密码长度至少为6位'}), 400
            
            # 使用username类和password类的结构添加新用户
            new_user = {
                'username': username_value,
                'password': password_value,
                'qq': ''
            }
            users.append(new_user)
            message = '用户添加成功'
            
        elif action == 'edit':
            # 查找并更新用户
            user_found = False
            for user in users:
                if user.get('username') == username_value:
                    # 密码长度验证
                    if len(password_value) < 6:
                        return jsonify({'status': 'error', 'message': '密码长度至少为6位'}), 400
                    
                    # 更新用户密码
                    user['password'] = password_value
                    # 更新用户QQ（如果提供）
                    if 'qq' in data:
                        user['qq'] = data.get('qq', '')
                    user_found = True
                    message = '用户更新成功'
                    break
            
            if not user_found:
                return jsonify({'status': 'error', 'message': '用户不存在'}), 404
            
        elif action == 'delete':
            # 防止删除默认测试用户
            if username_value == 'testuser':
                return jsonify({'status': 'error', 'message': '不能删除默认测试用户'}), 403
            
            # 查找并删除用户
            user_found = False
            for i, user in enumerate(users):
                if user.get('username') == username_value:
                    del users[i]
                    user_found = True
                    message = '用户删除成功'
                    break
            
            if not user_found:
                return jsonify({'status': 'error', 'message': '用户不存在'}), 404
            
        else:
            return jsonify({'status': 'error', 'message': '无效的操作类型'}), 400
        
        # 保存更新后的用户数据
        os.makedirs('user', exist_ok=True)
        with open(users_file, 'w', encoding='utf-8') as f:
            json.dump(user_data, f, ensure_ascii=False, indent=4)
        
        return jsonify({'status': 'success', 'message': message})
        
    except Exception as e:
        print(f"用户管理错误: {str(e)}")
        return jsonify({'status': 'error', 'message': f'服务器错误: {str(e)}'}), 500

@app.route('/admin')
@require_admin_token
def admin():
    """管理员控制面板页面"""
    
    disk_info = get_disk_usage()  # 获取磁盘信息
    sys_resources = get_system_resources()  # 获取系统资源信息
    
    # 构建disk_space字典以匹配模板需求
    disk_space = {
        'percent': disk_info['usage_percent'],
        'used': disk_info['upload_used'],
        'free': disk_info['available'],
        'total': disk_info['upload_total']
    }
    
    # 获取其他需要的数据
    files = get_file_list()
    share_folder = system_config['upload_folder']
    disk = get_disk_usage()
    
    # 计算总下载次数
    total_downloads = sum(f.get('download_count', 0) for f in files)
    
    # 获取用户列表 - 使用username类和password类的结构
    users = []
    users_file = os.path.join('user', 'user.json')
    if os.path.exists(users_file):
        try:
            with open(users_file, 'r', encoding='utf-8') as f:
                user_data = json.load(f)
                # 从users数组中提取用户信息
                if 'users' in user_data:
                    for user in user_data['users']:
                        users.append({
                            'username': user.get('username'),
                            'qq': user.get('qq', '')
                        })
        except Exception as e:
            print(f"读取用户列表失败: {str(e)}")
    
    return render_template(
        'admin.html',
        disk_space=disk_space,
        files=files,
        users=users,
        system_config=system_config,
        share_folder=share_folder,
        max_file_size=system_config['max_file_size'],
        max_total_size=system_config['max_total_size'],
        system_total=convert_size(disk['system_total']),
        system_used=convert_size(disk['system_used']),
        upload_used=convert_size(disk['upload_used']),
        upload_total=convert_size(disk['upload_total']),
        service_start=SERVICE_START_TIME.strftime("%Y-%m-%d %H:%M:%S"),
        uptime=str(datetime.now() - SERVICE_START_TIME),
        # 系统资源信息
        cpu_percent=sys_resources['cpu_percent'],
        mem_percent=sys_resources['mem_percent'],
        mem_total=convert_size(sys_resources['mem_total']),
        mem_used=convert_size(sys_resources['mem_used']),
        interfaces=sys_resources['interfaces'],
        # 网络配置
        port=system_config['port'],
        network_interface=system_config['network_interface'],
        # 总下载次数
        total_downloads=total_downloads,
        
    )


@app.route('/admin/login', methods=['GET'], endpoint='admin_login_get')
def admin_login_get():
    """
    管理员登录页面
    如果私钥文件存在，直接重定向到admin页面
    """
    try:
        base_path = get_base_path()
        private_key_path = os.path.join(base_path, 'key', 'private_key.key')
        private_key_pem_path = os.path.join(base_path, 'key', 'private_key.pem')
        
        # 如果私钥文件存在，直接重定向到admin安全设置页面
        if os.path.exists(private_key_path) or os.path.exists(private_key_pem_path):
            # 生成一个临时admin_token，允许当前会话访问
            session['admin_token'] = os.urandom(32).hex()
            session['admin_username'] = 'admin'
            session.permanent = True
            print("私钥文件存在，直接重定向到admin安全设置页面")
            return redirect('/admin#security')
    except Exception as e:
        print(f"检查私钥文件时出错: {e}")
    
    # 私钥文件不存在，显示登录页面
    return render_template('admin_login.html')


def load_public_key():
    """
    从key文件夹加载RSA公钥
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.backends import default_backend
        
        # 加载key文件夹中的key.pem文件作为公钥
        public_key_path = os.path.join(app.root_path, 'key', 'key.pem')
        
        # 确保文件夹存在
        key_dir = os.path.join(app.root_path, 'key')
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)
        
        # 如果公钥文件不存在或有问题，使用简单的管理员密码登录方式
        if not os.path.exists(public_key_path):
            print(f"公钥文件不存在: {public_key_path}")
            return None
            
        with open(public_key_path, 'rb') as key_file:
            key_data = key_file.read()
            try:
                public_key = load_pem_public_key(
                    key_data,
                    backend=default_backend()
                )
                return public_key
            except Exception as inner_e:
                print(f"解析公钥文件失败: {inner_e}")
                return None
    except Exception as e:
        print(f"加载公钥过程发生错误: {e}")
        return None


def verify_private_key(private_key_content, passphrase=None):
    """
    验证私钥文件的有效性，使用RSA密钥对验证机制：
    1. 随机生成一个数字
    2. 使用服务端公钥加密该数字
    3. 使用上传的私钥解密密文
    4. 比较解密结果和原数字是否一致
    
    Args:
        private_key_content: 私钥文件内容（UTF-8编码）
        passphrase: 私钥密码（可选）
        
    Returns:
        如果私钥有效返回True，否则返回False
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        import os
        import sys
        import json
        
        # 加载私钥，支持带密码的私钥
        password_bytes = passphrase.encode('utf-8') if passphrase else None
        
        # 确保私钥内容正确处理换行符
        private_key_content = private_key_content.strip()
        if not private_key_content.startswith('-----BEGIN'):
            # 尝试添加缺失的开始标记
            private_key_content = '-----BEGIN RSA PRIVATE KEY-----\n' + private_key_content
        if not private_key_content.endswith('-----END RSA PRIVATE KEY-----'):
            # 尝试添加缺失的结束标记
            if not private_key_content.endswith('-----END'):
                private_key_content = private_key_content + '\n-----END RSA PRIVATE KEY-----'
        
        # 规范化换行符为\n
        private_key_content = private_key_content.replace('\r\n', '\n')
        
        # 加载上传的私钥
        private_key = load_pem_private_key(
            private_key_content.encode('utf-8'),
            password=password_bytes,
            backend=default_backend()
        )
        
        # 加载服务端公钥
        base_path = get_base_path()
        public_key_path = os.path.join(base_path, 'key', 'key.pem')
        
        if not os.path.exists(public_key_path):
            print(f"公钥文件不存在: {public_key_path}")
            return False
            
        with open(public_key_path, 'rb') as key_file:
            key_data = key_file.read()
            public_key = load_pem_public_key(
                key_data,
                backend=default_backend()
            )
        
        # 获取公钥密钥长度（单位：位）
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        if isinstance(public_key, RSAPublicKey):
            key_size = public_key.key_size
            print(f"检测到RSA公钥，密钥长度: {key_size} 位")
            
            # 计算最大可用加密长度：密钥长度/8 - 2*SHA256长度 - 2 = 密钥长度/8 - 66字节
            max_data_length = key_size // 8 - 66
            print(f"RSA最大可用加密长度: {max_data_length} 字节")
        else:
            print("检测到非RSA公钥，使用默认密钥长度")
            key_size = 4096  # 默认4096位
            max_data_length = 512 - 66  # 4096位RSA的最大可用加密长度 (512 - 66 = 446字节)
        
        # 1. 生成安全长度的随机数
        import random
        # 确保随机数长度不超过最大可用加密长度
        # 生成一个长度不超过max_data_length的随机数字符串
        random_digits = str(random.randint(100000, 99999999999999999999999))
        random_number = random_digits.encode('utf-8')
        
        # 检查数据长度
        if len(random_number) > max_data_length:
            print(f"警告：随机数长度({len(random_number)}字节)超过最大可用加密长度({max_data_length}字节)，自动截断")
            # 截断到安全长度
            random_number = random_number[:max_data_length]
            random_digits = random_number.decode('utf-8')
        
        print(f"生成的随机数: {random_digits}")
        print(f"随机数长度: {len(random_number)} 字节")
        
        # 2. 使用服务端公钥加密随机数
        encrypted_data = public_key.encrypt(
            random_number,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"加密后的密文: {encrypted_data.hex()[:30]}...")
        
        # 3. 使用上传的私钥解密密文
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"解密后的结果: {decrypted_data.decode('utf-8')}")
        print(f"解密结果长度: {len(decrypted_data)} 字节")
        
        # 4. 比较解密结果和原随机数
        if decrypted_data == random_number:
            print("RSA密钥对验证成功: 解密结果与原数据一致")
            return True
        else:
            print("RSA密钥对验证失败: 解密结果与原数据不一致")
            return False
            
    except ValueError as e:
        print(f"私钥密码错误或私钥格式错误: {e}")
        return False
    except Exception as e:
        print(f"私钥验证失败: {e}")
        import traceback
        traceback.print_exc()
        return False


@app.route('/admin/login', methods=['POST'], endpoint='admin_login_post')
def admin_login_post():
    """
    管理员登录API - 支持私钥文件上传和手动输入私钥内容两种方式
    私钥验证流程：
    1. 验证私钥的有效性（包括密码验证和格式验证）
    2. 如果私钥能成功加载，即认为验证通过
    """
    try:
        # 只处理表单请求
        if request.content_type and request.content_type.startswith('multipart/form-data'):
            # 获取登录类型
            login_type = request.form.get('login_type', 'file')
            passphrase = request.form.get('passphrase')
            private_key_content = None
            
            if login_type == 'manual':
                # 手动输入私钥内容方式
                private_key_content = request.form.get('private_key_content', '').strip()
                
                if not private_key_content:
                    return jsonify({"status": "error", "message": "请输入私钥内容"})
                
                print("接收到手动输入的私钥内容，开始验证")
            else:
                # 默认的私钥文件上传方式
                # 获取上传的私钥文件
                if 'private_key' not in request.files:
                    return jsonify({"status": "error", "message": "请上传私钥文件"})
                
                private_key_file = request.files['private_key']
                
                # 验证文件名，支持.key和.pem格式
                if not private_key_file.filename:
                    return jsonify({"status": "error", "message": "未选择私钥文件"})
                
                if not (private_key_file.filename.lower().endswith('.key') or 
                        private_key_file.filename.lower().endswith('.pem')):
                    return jsonify({"status": "error", "message": "请上传.key或.pem格式的私钥文件"})
                
                # 读取私钥文件内容 - 总是重新读取，确保实时更新
                private_key_content = private_key_file.read().decode('utf-8')
                print(f"接收到私钥文件: {private_key_file.filename}，开始验证")
            
            # 增强的私钥验证（支持带密码的私钥和正确处理换行符）
            if not verify_private_key(private_key_content, passphrase):
                print("私钥验证失败: 私钥格式错误或密码不正确")
                return jsonify({"status": "error", "message": "私钥验证失败，请检查私钥格式和密码"})
            
            print("私钥验证成功")
            
            # 验证成功，生成安全的会话令牌
            session_token = os.urandom(32).hex()
            session['admin_token'] = session_token
            session['admin_username'] = 'admin'
            
            # 设置会话过期时间（30分钟）
            session.permanent = True
            
            # 登录成功，重定向到管理员页面
            return jsonify({"status": "success", "redirect": "/admin"})
        
        return jsonify({"status": "error", "message": "不支持的请求格式"})
    except ValueError as e:
        print(f"值错误: {e}")
        return jsonify({"status": "error", "message": f"输入错误: {str(e)}"})
    except UnicodeDecodeError:
        return jsonify({"status": "error", "message": "无法解析私钥文件，请确保文件格式正确"})
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"管理员登录失败: {e}")
        return jsonify({"status": "error", "message": "登录过程中发生错误，请重试"}), 500



@app.route('/admin/logout')
@require_admin_token
def admin_logout():
    """管理员登出"""
    # 清除管理员token
    session.pop('admin_token', None)
    session.pop('admin_username', None)
    
    # 检查是否有普通用户的token需要删除
    token = session.get('token')
    if token and token in tokens:
        del tokens[token]
        save_tokens()
    
    # 清除普通用户的session信息
    session.pop('user_logged_in', None)
    session.pop('username', None)
    session.pop('token', None)
    
    return redirect('/admin/login')


@app.route('/@vite/client')
def vite_client():
    """
    处理@vite/client请求，返回204 No Content，避免404错误日志
    """
    return '', 204


@app.route('/admin/get-private-key')
@require_admin_token
def get_private_key():
    """
    获取RSA私钥内容
    """
    try:
        base_path = get_base_path()
        private_key_path = os.path.join(base_path, 'key', 'private_key.key')
        
        if os.path.exists(private_key_path):
            with open(private_key_path, 'r') as f:
                private_key_content = f.read()
            return private_key_content, 200, {'Content-Type': 'text/plain'}
        else:
            return jsonify({"status": "error", "message": "私钥文件不存在"}), 404
    except Exception as e:
        print(f"获取私钥内容失败: {e}")
        return jsonify({"status": "error", "message": "获取私钥内容失败"}), 500


@app.route('/admin/download-private-key')
@require_admin_token
def download_private_key():
    """
    下载RSA私钥文件
    下载完成后删除服务端的私钥文件
    """
    try:
        base_path = get_base_path()
        private_key_path = os.path.join(base_path, 'key', 'private_key.key')
        private_key_pem_path = os.path.join(base_path, 'key', 'private_key.pem')
        
        if os.path.exists(private_key_path):
            # 先读取文件内容，然后删除文件，最后返回文件内容
            with open(private_key_path, 'rb') as f:
                private_key_content = f.read()
            
            # 删除服务端的私钥文件
            os.remove(private_key_path)
            print(f"已删除服务端私钥文件: {private_key_path}")
            
            # 如果存在private_key.pem文件，也一并删除
            if os.path.exists(private_key_pem_path):
                os.remove(private_key_pem_path)
                print(f"已删除服务端私钥PEM文件: {private_key_pem_path}")
            
            # 返回文件内容给用户下载
            return Response(private_key_content, 
                           mimetype='application/octet-stream',
                           headers={'Content-Disposition': f'attachment; filename=private_key.key'})
        else:
            return jsonify({"status": "error", "message": "私钥文件不存在"}), 404
    except Exception as e:
        print(f"下载私钥文件失败: {e}")
        return jsonify({"status": "error", "message": "下载私钥文件失败"}), 500


# 文件操作API
@app.route('/api/files')
@login_required
def api_files():
    """获取文件列表API"""
    files = get_file_list()
    disk = get_disk_usage()
    
    # 添加前端需要的字段
    formatted_files = []
    for file in files:
        formatted_files.append({
            'filename': file['filename'],
            'name': file['name'],
            'size': file['size'],
            'modified': file['modified'],
            'download_count': file['download_count'],
            # 添加 hash 字段(这里用文件名代替)
            'hash': file['name']
        })
    
    return jsonify({
        'files': formatted_files,
        'disk_used': disk['upload_used'],
        'max_storage': system_config['max_total_size'] * 1024 * 1024
    })


@app.route('/api/my_files')
@login_required
def api_my_files():
    """获取当前用户上传的文件列表API"""
    username = session.get('username', 'unknown')
    metadata = load_metadata()
    disk = get_disk_usage()
    
    # 获取当前用户上传的文件
    my_files = []
    for filename, file_meta in metadata.items():
        if file_meta.get('user') == username:
            # 获取文件的完整信息
            file_path = os.path.join(system_config['upload_folder'], filename)
            if os.path.exists(file_path) and os.path.isfile(file_path):
                try:
                    file_info = os.stat(file_path)
                    my_files.append({
                        'filename': filename,
                        'name': filename,
                        'size': file_info.st_size,
                        'modified': file_info.st_mtime,
                        'created': file_info.st_ctime,
                        'download_count': file_meta.get('download_count', 0),
                        'hash': filename
                    })
                except Exception as e:
                    print(f"获取文件信息失败: {filename}, 错误: {e}")
    
    # 按修改时间排序(最新在上)
    my_files.sort(key=lambda x: x['modified'], reverse=True)
    
    return jsonify({
        'files': my_files,
        'disk_used': disk['upload_used'],
        'max_storage': system_config['max_total_size'] * 1024 * 1024
    })


@app.route('/api/upload', methods=['POST'])
@login_required
def upload():
    """文件上传API"""
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "未选择文件"})
    
    file = request.files['file']
    
    # 验证文件名
    if not file.filename or '.' not in file.filename:
        return jsonify({"status": "error", "message": "无效的文件名"})
    
    # 检查文件扩展名是否允许上传
    if not is_file_extension_allowed(file.filename):
        config = get_file_extension_config()
        if config['enabled']:
            if config['mode'] == 'whitelist':
                allowed_extensions = ', '.join(config['extensions'])
                return jsonify({"status": "error", "message": f"只允许上传以下类型的文件：{allowed_extensions}"})
            else:
                disallowed_extensions = ', '.join(config['extensions'])
                return jsonify({"status": "error", "message": f"不允许上传以下类型的文件：{disallowed_extensions}"})
        return jsonify({"status": "error", "message": "文件类型不允许上传"})
    
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)  # 重置文件指针
    
    # 检查单个文件大小限制
    max_size = system_config['max_file_size'] * 1024 * 1024
    if file_size > max_size:
        return jsonify({
            "status": "error",
            "message": f"文件大小超过限制 ({convert_size(max_size)})"
        })
    
    # 检查总空间(更严格的检查)
    disk = get_disk_usage()
    if file_size > disk['available']:
        return jsonify({
            "status": "error",
            "message": f"磁盘空间不足(可用空间：{convert_size(disk['available'])})"
        })
    
    # 添加全局上传锁,防止并发上传导致空间超限
    with upload_lock:
        # 再次检查空间(防止在检查期间有其他文件上传)
        disk = get_disk_usage()
        if file_size > disk['available']:
            return jsonify({
                "status": "error",
                "message": "空间不足,请稍后再试"
            })
        
        # 保留原始中文文件名，仅移除不安全字符
        original_filename = file.filename
        # 移除路径分隔符和其他不安全字符，但保留中文
        filename = original_filename.replace('..', '').replace('/', '').replace('\\', '')
        # 处理空文件名情况
        if not filename or '.' not in filename:
            return jsonify({"status": "error", "message": "无效的文件名"})
        
        save_path = os.path.join(system_config['upload_folder'], filename)
        
        # 处理重名文件
        counter = 1
        name, ext = os.path.splitext(filename)
        new_name = filename  # 初始化new_name变量
        while os.path.exists(save_path):
            new_name = f"{name}_{counter}{ext}"
            save_path = os.path.join(system_config['upload_folder'], new_name)
            counter += 1
        filename = new_name
        
        try:
            file.save(save_path)
            # 获取当前登录用户的用户名
            username = session.get('username', 'unknown')
            # 更新文件元数据，记录上传用户
            update_metadata(filename, 'upload', username)
            # 更新用户的文件列表
            update_user_files(username, filename, 'add')
            return jsonify({"status": "success", "filename": filename})
        except Exception as e:
            return jsonify({"status": "error", "message": f"保存失败: {str(e)}"})


@app.route('/api/delete_file', methods=['POST'])
@require_admin_token
def api_delete_file():
    """管理员删除文件API"""
    try:
        # 从JSON数据获取文件名
        data = request.get_json()
        filename = data.get('filename')
        
        if not filename:
            return jsonify({"status": "error", "message": "文件名不能为空"}), 400
        
        # 安全检查，防止目录遍历攻击
        if '../' in filename or not re.match(r'^[\w\-. \u4e00-\u9fa5]+$', filename):
            return jsonify({"status": "error", "message": "无效的文件名"}), 400
        
        file_path = os.path.join(system_config['upload_folder'], filename)
        
        # 确保文件在上传目录内
        real_upload_dir = os.path.realpath(system_config['upload_folder'])
        real_file_path = os.path.realpath(file_path)
        
        if not real_file_path.startswith(real_upload_dir):
            return jsonify({"status": "error", "message": "文件不在上传目录内"}), 400
        
        # 检查是否为符号链接
        if os.path.islink(file_path):
            return jsonify({"status": "error", "message": "不能删除符号链接文件"}), 400
        
        if not os.path.exists(file_path):
            return jsonify({"status": "error", "message": "文件不存在"}), 404
        
        try:
            # 在删除文件前，获取文件的上传用户
            metadata = load_metadata()
            file_metadata = metadata.get(filename, {})
            upload_user = file_metadata.get('user', 'unknown')
            
            # 删除文件
            os.remove(file_path)
            
            # 更新元数据
            update_metadata(filename, 'delete')
            
            # 从用户的文件列表中移除该文件
            update_user_files(upload_user, filename, 'remove')
            
            return jsonify({"status": "success", "message": "文件已删除"})
        except Exception as e:
            return jsonify({"status": "error", "message": f"删除失败: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"请求处理失败: {str(e)}"}), 500


@app.route('/api/delete_my_file', methods=['POST'])
@login_required
def api_delete_my_file():
    """普通用户删除自己上传的文件API"""
    try:
        # 从JSON数据获取文件名
        data = request.get_json()
        filename = data.get('filename')
        
        if not filename:
            return jsonify({"status": "error", "message": "文件名不能为空"}), 400
        
        # 安全检查，防止目录遍历攻击
        if '../' in filename or not re.match(r'^[\w\-. \u4e00-\u9fa5]+$', filename):
            return jsonify({"status": "error", "message": "无效的文件名"}), 400
        
        # 获取当前用户
        current_user = session.get('username', 'unknown')
        
        # 检查文件是否为当前用户上传
        metadata = load_metadata()
        file_metadata = metadata.get(filename, {})
        upload_user = file_metadata.get('user', 'unknown')
        
        if upload_user != current_user:
            return jsonify({"status": "error", "message": "无权删除该文件"}), 403
        
        file_path = os.path.join(system_config['upload_folder'], filename)
        
        # 确保文件在上传目录内
        real_upload_dir = os.path.realpath(system_config['upload_folder'])
        real_file_path = os.path.realpath(file_path)
        
        if not real_file_path.startswith(real_upload_dir):
            return jsonify({"status": "error", "message": "文件不在上传目录内"}), 400
        
        # 检查是否为符号链接
        if os.path.islink(file_path):
            return jsonify({"status": "error", "message": "不能删除符号链接文件"}), 400
        
        if not os.path.exists(file_path):
            return jsonify({"status": "error", "message": "文件不存在"}), 404
        
        try:
            # 删除文件
            os.remove(file_path)
            
            # 更新元数据
            update_metadata(filename, 'delete')
            
            # 从用户的文件列表中移除该文件
            update_user_files(current_user, filename, 'remove')
            
            return jsonify({"status": "success", "message": "文件已删除"})
        except Exception as e:
            return jsonify({"status": "error", "message": f"删除失败: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"请求处理失败: {str(e)}"}), 500


# 系统信息API
@app.route('/api/sysinfo')
def api_sysinfo():
    """获取系统信息API"""
    disk = get_disk_usage()
    files = get_file_list()
    total_downloads = sum(f['download_count'] for f in files)
    
    return jsonify({
        'disk': disk,
        'config': {
            'max_file_size': system_config['max_file_size'],
            'max_total_size': system_config['max_total_size'],
            'app_name': system_config['app_name'],
            'app_version': system_config['app_version']
        },
        'file_count': len(files),
        'service_start': SERVICE_START_TIME.isoformat(),
        'uptime': str(datetime.now() - SERVICE_START_TIME),
        'total_downloads': total_downloads
    })


@app.route('/api/system/config')
def get_system_config():
    """获取系统配置API"""
    return jsonify({
        'max_file_size': system_config['max_file_size'],
        'max_total_size': system_config['max_total_size'],
        'app_name': system_config['app_name'],
        'app_version': system_config['app_version']
    })


@app.route('/api/update_config', methods=['POST'], endpoint='update_config')
@require_admin_token
def api_update_config():
    """更新系统配置API"""
    try:
        data = request.get_json()
        
        # 更新存储配置
        if 'max_storage' in data:
            max_storage = float(data['max_storage'])
            if max_storage <= 0:
                return jsonify({"status": "error", "message": "存储空间必须大于0"}), 400
            system_config['max_total_size'] = max_storage * 1024  # GB转MB
        
        if 'max_file_size' in data:
            max_file_size = float(data['max_file_size'])
            if max_file_size <= 0:
                return jsonify({"status": "error", "message": "文件大小必须大于0"}), 400
            system_config['max_file_size'] = max_file_size
        
        # 更新极验配置
        if 'geetest_id' in data:
            system_config['geetest_id'] = data['geetest_id']

        if 'geetest_key' in data:
            system_config['geetest_key'] = data['geetest_key']
            
        # 更新离线下载配置
        if 'offline_download_enabled' in data:
            system_config['offline_download_enabled'] = data['offline_download_enabled'] == 'on' or data['offline_download_enabled'] == True
        else:
            # 如果没有发送此参数，默认为禁用
            system_config['offline_download_enabled'] = False

        # 更新端口配置
        if 'port' in data:
            port = int(data['port'])
            if port < 1024 or port > 65535:
                return jsonify({"status": "error", "message": "端口必须在1024-65535之间"}), 400
            system_config['port'] = port
        
        # 更新网络接口配置
        if 'network_interface' in data:
            system_config['network_interface'] = data['network_interface']
        
        save_config()
        return jsonify({"status": "success", "config": system_config})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/update_security_settings', methods=['POST'], endpoint='update_security_settings')
@require_admin_token
def api_update_security_settings():
    """更新安全设置API"""
    try:
        data = request.get_json()
        
        # 更新用户登录启用设置
        if 'user_login_enabled' in data:
            # 处理复选框逻辑：'on'、true、1都视为启用
            system_config['user_login_enabled'] = data['user_login_enabled'] == 'on' or \
                                                data['user_login_enabled'] is True or \
                                                data['user_login_enabled'] == 1 or \
                                                str(data['user_login_enabled']).lower() == 'true'
        
        save_config()
        return jsonify({"status": "success", "config": system_config})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/token_settings', methods=['GET', 'POST'])
@require_admin_token
def api_token_settings():
    """Token设置API"""
    global TOKEN_EXPIRY
    
    if request.method == 'GET':
        # 获取当前token设置
        return jsonify({
            'status': 'success',
            'token_expiry': TOKEN_EXPIRY
        })
    elif request.method == 'POST':
        # 更新token设置
        try:
            data = request.get_json()
            new_expiry = data.get('token_expiry')
            
            if new_expiry and isinstance(new_expiry, int) and new_expiry > 0:
                TOKEN_EXPIRY = new_expiry
                # 将TOKEN_EXPIRY保存到配置文件中
                system_config['token_expiry'] = TOKEN_EXPIRY
                save_config()
                app.logger.info(f"更新Token有效期为: {TOKEN_EXPIRY}秒")
                return jsonify({"status": "success", "message": "Token设置已更新"})
            else:
                return jsonify({"status": "error", "message": "无效的Token有效期"}), 400
        except Exception as e:
            app.logger.error(f"更新Token设置失败: {str(e)}")
            return jsonify({"status": "error", "message": f"更新Token设置失败: {str(e)}"}), 500

@app.route('/api/manage_tokens', methods=['GET', 'POST'])
@require_admin_token
def api_manage_tokens():
    """管理Token API"""
    if request.method == 'GET':
        # 获取所有token信息
        tokens_info = []
        current_time = time.time()
        for token, info in tokens.items():
            is_expired = current_time >= info['expiry']
            tokens_info.append({
                'token': token,
                'username': info['username'],
                'expiry': info['expiry'],
                'is_expired': is_expired,
                'expiry_str': datetime.fromtimestamp(info['expiry']).strftime('%Y-%m-%d %H:%M:%S')
            })
        return jsonify({"status": "success", "tokens": tokens_info})
    elif request.method == 'POST':
        # 管理token（删除等操作）
        try:
            data = request.get_json()
            action = data.get('action')
            token = data.get('token')
            
            if action == 'delete' and token:
                if token in tokens:
                    del tokens[token]
                    save_tokens()
                    app.logger.info(f"管理员删除了Token: {token}")
                    return jsonify({"status": "success", "message": "Token已删除"})
                else:
                    return jsonify({"status": "error", "message": "Token不存在"}), 404
            else:
                return jsonify({"status": "error", "message": "无效的操作或参数"}), 400
        except Exception as e:
            app.logger.error(f"管理Token失败: {str(e)}")
            return jsonify({"status": "error", "message": f"管理Token失败: {str(e)}"}), 500

@app.route('/api/check_config_file', methods=['GET'], endpoint='check_config_file')
@require_admin_token
def api_check_config_file():
    """
    检查并更新配置文件API
    
    此API允许管理员在不重启服务器的情况下，
    手动触发配置文件的检查和更新操作。
    """
    try:
        # 调用检查和更新配置文件的函数
        config_updated = check_and_update_config_file()
        
        # 重新加载配置
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8-sig') as f:
                saved_config = json.load(f)
                for key in saved_config:
                    if key in system_config:
                        system_config[key] = saved_config[key]
        
        if config_updated:
            return jsonify({"status": "success", "message": "配置文件已更新", "config": system_config})
        else:
            return jsonify({"status": "success", "message": "配置文件已是最新状态", "config": system_config})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/file_extensions', methods=['GET', 'POST'], endpoint='file_extensions')
@require_admin_token
def api_file_extensions():
    """文件扩展名黑白名单管理API"""
    try:
        if request.method == 'GET':
            # 获取当前配置
            config = get_file_extension_config()
            return jsonify({"status": "success", "config": config})
        elif request.method == 'POST':
            # 更新配置
            data = request.get_json()
            
            # 验证配置
            if 'enabled' not in data:
                return jsonify({"status": "error", "message": "缺少enabled字段"}), 400
            
            if 'mode' not in data or data['mode'] not in ['whitelist', 'blacklist']:
                return jsonify({"status": "error", "message": "mode字段无效，必须是whitelist或blacklist"}), 400
            
            if 'extensions' not in data or not isinstance(data['extensions'], list):
                return jsonify({"status": "error", "message": "extensions字段无效，必须是数组"}), 400
            
            # 保存配置
            config = {
                'enabled': data['enabled'],
                'mode': data['mode'],
                'extensions': data['extensions']
            }
            
            if save_file_extension_config(config):
                return jsonify({"status": "success", "message": "文件扩展名配置已更新", "config": config})
            else:
                return jsonify({"status": "error", "message": "保存配置失败"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/theme_settings', methods=['GET', 'POST'], endpoint='theme_settings')
@require_admin_token
def api_theme_settings():
    """
    主题设置API，用于获取和保存主题颜色设置
    """
    try:
        if request.method == 'GET':
            # 获取当前主题设置
            colors = get_theme_settings()
            return jsonify({"status": "success", "colors": colors})
        elif request.method == 'POST':
            # 保存主题设置
            data = request.get_json()
            # 保存主题颜色设置
            save_theme_settings(data)
            app.logger.info("管理员更新了主题设置")
            return jsonify({"status": "success", "message": "主题设置已保存", "colors": data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/file_content', methods=['GET'], endpoint='file_content')
def api_file_content():
    """
    获取文件内容API，用于文件预览
    """
    try:
        filename = request.args.get('filename')
        if not filename:
            return jsonify({"status": "error", "message": "缺少文件名参数"}), 400
        
        # 直接使用解码后的文件名，因为URL参数已经经过URL编码
        file_path = os.path.join(system_config['upload_folder'], filename)
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return jsonify({"status": "error", "message": "文件不存在"}), 404
        
        # 检查文件是否在允许的目录内（防止路径遍历攻击）
        real_upload_dir = os.path.realpath(system_config['upload_folder'])
        real_file_path = os.path.realpath(file_path)
        if not real_file_path.startswith(real_upload_dir):
            return jsonify({"status": "error", "message": "非法的文件路径"}), 403
        
        # 限制文件大小，防止过大的文件导致内存问题
        max_preview_size = 10 * 1024 * 1024  # 10MB
        if os.path.getsize(file_path) > max_preview_size:
            return jsonify({"status": "error", "message": "文件过大，无法预览"}), 413
        
        # 读取文件内容
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return content, 200, {'Content-Type': 'text/plain'}
    except Exception as e:
        app.logger.error(f"获取文件内容失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# 用户登录检查装饰器


# 从user.json读取用户数据进行认证
# 用户识别类定义
class username:
    """用户名类，用于用户识别"""
    def __init__(self, value):
        self.value = value
    
    def __eq__(self, other):
        if isinstance(other, username):
            return self.value == other.value
        return self.value == other
    
    def __str__(self):
        return self.value

class password:
    """密码类，用于用户认证"""
    def __init__(self, value):
        self.value = value
    
    def __eq__(self, other):
        if isinstance(other, password):
            return self.value == other.value
        return self.value == other
    
    def __str__(self):
        return self.value


def validate_user(username_value, password_value):
    """
    从user.json文件中验证用户凭据
    使用username类和password类进行用户识别和验证
    
    Args:
        username_value: 用户名
        password_value: 密码
        
    Returns:
        bool: 用户凭据是否有效
    """
    try:
        # 将输入值转换为对应的类
        input_username = username(username_value)
        input_password = password(password_value)
        
        # 读取user.json文件
        user_file_path = os.path.join('user', 'user.json')
        if not os.path.exists(user_file_path):
            print("用户数据文件不存在")
            return False
            
        with open(user_file_path, 'r', encoding='utf-8') as f:
            user_data = json.load(f)
            
        # 获取用户列表
        users = user_data.get('users', [])
        
        # 查找并验证用户 - 使用类进行比较
        for user in users:
            stored_username = username(user.get('username'))
            stored_password = password(user.get('password'))
            
            if stored_username == input_username and stored_password == input_password:
                return True
                
        return False
        
    except Exception as e:
        print(f"用户验证错误: {e}")
        return False

# 页面路由
@app.route('/')
def index():
    """用户登录页面 - 根据配置决定显示登录页还是直接以游客身份进入"""
    # 检查是否已经登录
    if 'user_logged_in' in session and session['user_logged_in']:
        # 根据用户名决定重定向到哪个页面
        if session.get('username') == '游客':
            return redirect(url_for('guest_page'))
        else:
            return redirect(url_for('user_page'))
    
    # 显示登录页面，无论是否启用用户登录
    return render_template(
        'index.html',
        app_name=system_config['app_name'],
        user_login_enabled=system_config.get('user_login_enabled', True)
    )

@app.route('/guest/login', methods=['GET'])
def guest_login():
    """游客登录处理 - 直接以游客身份进入系统"""
    # 检查是否启用用户登录
    if system_config.get('user_login_enabled', True):
        # 如果启用了用户登录，重定向到登录页面
        app.logger.info(f"用户登录功能已启用，不允许直接游客登录，重定向到登录页")
        return redirect(url_for('index'))
    
    # 清空旧session
    session.clear()
    # 设置session为永久会话
    session.permanent = True
    # 设置登录标记和游客信息
    session['user_logged_in'] = True
    session['username'] = '游客'
    session['login_time'] = datetime.now().isoformat()
    # 记录详细日志
    app.logger.info(f"游客登录成功，自动创建会话")
    # 重定向到游客专用页面
    return redirect(url_for('guest_page'))

@app.route('/login', methods=['POST'])
def login():
    """用户登录处理"""
    # 尝试从JSON获取数据（前端使用fetch发送JSON）
    if request.is_json:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
    else:
        # 兼容表单提交方式
        username = request.form.get('username')
        password = request.form.get('password')
    
    if not username or not password:
        if request.is_json:
            return jsonify({'status': 'error', 'message': '用户名和密码不能为空'})
        else:
            flash('用户名和密码不能为空')
            return redirect(url_for('index'))
    
    if validate_user(username, password):
        # 清空旧session
        session.clear()
        # 设置session为永久会话
        session.permanent = True
        # 设置登录标记和用户信息
        session['user_logged_in'] = True
        session['username'] = username
        session['login_time'] = datetime.now().isoformat()
        
        # 删除该用户所有现有的token，实现同一用户多设备登录时旧token失效
        # 这样每次登录都会生成新的token，旧的token会被删除
        tokens_to_delete = []
        for token, info in tokens.items():
            if info['username'] == username:
                tokens_to_delete.append(token)
        
        for token in tokens_to_delete:
            del tokens[token]
        
        # 生成新token
        token = generate_token()
        # 存储token信息
        tokens[token] = {
            'username': username,
            'expiry': time.time() + TOKEN_EXPIRY
        }
        # 保存tokens到文件
        save_tokens()
        app.logger.info(f"用户 {username} 登录成功，生成新token: {token}")
        
        # 直接重定向到用户页面，绕过前端可能的问题
        if request.is_json:
            # 对于JSON请求，返回token和重定向指令
            return jsonify({
                'status': 'success', 
                'token': token,
                'username': username,
                'redirect': '/user'
            })
        else:
            # 对于表单提交，将token存储在session中
            session['token'] = token
            return redirect(url_for('user_page'))
    else:
        app.logger.info(f"用户 {username} 登录失败：用户名或密码错误")
        if request.is_json:
            return jsonify({'status': 'error', 'message': '用户名或密码错误'})
        else:
            flash('用户名或密码错误')
            return redirect(url_for('index'))

@app.route('/user')
@login_required
def user_page():
    """用户登录后的文件管理页面"""
    # 记录详细的session信息
    username = session.get('username', '未知用户')
    has_login_time = 'login_time' in session
    app.logger.info(f"访问用户页面，用户名: {username}, 登录时间存在: {has_login_time}")
    
    # 检查是否为游客用户，如果是则重定向到游客页面
    if username == '游客':
        app.logger.info(f"游客用户访问用户页面，重定向到游客专用页面")
        return redirect(url_for('guest_page'))
    
    disk = get_disk_usage()
    files = get_file_list()
    
    # 获取用户的QQ信息
    user_qq = ''
    users_file = os.path.join('user', 'user.json')
    if os.path.exists(users_file):
        with open(users_file, 'r', encoding='utf-8') as f:
            user_data = json.load(f)
            users = user_data.get('users', [])
            for user in users:
                if user.get('username') == username:
                    user_qq = user.get('qq', '')
                    break
    
    # 计算统计信息
    login_time = session.get('login_time', '')
    # 检查login_time的类型，确保只对datetime对象调用strftime
    if isinstance(login_time, datetime):
        login_time = login_time.strftime('%Y-%m-%d %H:%M:%S')
    # 如果是字符串，直接使用
    elif not login_time:
        login_time = ''
    
    # 获取元数据
    metadata = load_metadata()
    
    # 统计用户上传的文件
    user_files = []
    for filename, file_info in metadata.items():
        if file_info.get('user') == username:
            user_files.append({
                'name': filename,
                'size': file_info.get('size', 0),
                'created': file_info.get('created', 0)
            })
    
    total_uploads = len(user_files)
    total_upload_size = sum(file['size'] for file in user_files)
    
    last_upload_time = ''
    if user_files:
        # 按创建时间排序，取最新的
        latest_file = max(user_files, key=lambda f: f['created'])
        last_upload_time = datetime.fromtimestamp(latest_file['created']).strftime('%Y-%m-%d %H:%M:%S')
    
    return render_template(
        'user.html',
        files=files,
        app_name=system_config['app_name'],
        total_space=convert_size(disk['upload_total']),
        used_space=convert_size(disk['upload_used']),
        free_space=convert_size(disk['available']),
        max_file_size=system_config['max_file_size'],
        usage_percent=disk['usage_percent'],
        username=username,
        qq=user_qq,
        login_time=login_time,
        total_uploads=total_uploads,
        total_upload_size=convert_size(total_upload_size),
        last_upload_time=last_upload_time
    )

@app.route('/guest')
@login_required
def guest_page():
    """游客专用页面"""
    # 记录详细的session信息
    username = session.get('username', '未知用户')
    has_login_time = 'login_time' in session
    app.logger.info(f"访问游客页面，用户名: {username}, 登录时间存在: {has_login_time}")
    
    disk = get_disk_usage()
    files = get_file_list()
    
    return render_template(
        'guest.html',
        files=files,
        app_name=system_config['app_name'],
        system_version=system_config['app_version'],
        total_space=convert_size(disk['upload_total']),
        used_space=convert_size(disk['upload_used']),
        free_space=convert_size(disk['available']),
        max_file_size=system_config['max_file_size'],
        usage_percent=disk['usage_percent'],
        username=username
    )

@app.route('/api/token_expiry')
def get_token_expiry():
    """获取当前token的剩余有效期"""
    # 从请求头获取token
    token = request.headers.get('Authorization') or request.headers.get('X-Token')
    if token and token.startswith('Bearer '):
        token = token[7:]
    
    # 从session获取token（如果有）
    if not token:
        token = session.get('token')
    
    if not token or token not in tokens:
        return jsonify({'status': 'error', 'message': '无效的token'}), 401
    
    # 计算剩余时间
    current_time = time.time()
    expiry_time = tokens[token]['expiry']
    remaining_seconds = max(0, int(expiry_time - current_time))
    
    return jsonify({
        'status': 'success',
        'token': token,
        'expiry': int(expiry_time),
        'remaining_seconds': remaining_seconds,
        'expiry_time': datetime.fromtimestamp(expiry_time).isoformat()
    })

@app.route('/logout')
def logout():
    """用户登出"""
    # 从session获取token
    token = session.get('token')
    if token:
        # 删除服务器端的token
        if token in tokens:
            del tokens[token]
            save_tokens()
    
    # 从请求头获取token（如果有）
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header[7:]
        if token in tokens:
            del tokens[token]
            save_tokens()
    
    # 清除session中的用户信息
    session.pop('user_logged_in', None)
    session.pop('username', None)
    session.pop('token', None)
    return redirect(url_for('index'))

@app.route('/markdown-viewer')
def markdown_viewer():
    """Markdown文件查看器"""
    filename = request.args.get('file')
    theme = request.args.get('theme', 'light')
    return render_template('markdown-viewer.html', filename=filename, theme=theme)

@app.route('/bug_report')
def bug_report():
    """Bug报告页面"""
    return render_template('bug_report.html')

@app.route('/api/github-update-info')
def api_github_update_info():
    """获取GitHub更新信息"""
    try:
        import requests
        import markdown
        import re
        from datetime import datetime
        
        # GitHub仓库API URL
        repo_url = "https://api.github.com/repos/508364/Announcement/contents/Update/FileSharePlatform-Adofai-Simplified-Version"
        
        # 发送请求获取目录内容，添加 verify=False 跳过SSL证书验证
        response = requests.get(repo_url, verify=False)
        response.raise_for_status()
        
        files = response.json()
        md_files = [f for f in files if f['name'].endswith('.md')]
        
        if not md_files:
            return jsonify({"status": "error", "message": "未找到.md文件"})
        
        # 尝试从文件名中提取日期并排序，获取最新的.md文件
        def extract_date_from_filename(filename):
            # 尝试匹配文件名中的日期格式（如 2023-12-31 或 20231231）
            date_match = re.search(r'(\d{4}[-_]?\d{2}[-_]?\d{2})', filename)
            if date_match:
                date_str = date_match.group(1).replace('_', '-')
                try:
                    return datetime.strptime(date_str, '%Y-%m-%d')
                except ValueError:
                    try:
                        return datetime.strptime(date_str, '%Y%m%d')
                    except ValueError:
                        pass
            # 如果无法提取日期，返回一个较早的日期
            return datetime(1970, 1, 1)
        
        # 按日期排序，最新的在前
        md_files.sort(key=lambda x: extract_date_from_filename(x['name']), reverse=True)
        md_file = md_files[0]
        file_url = md_file['download_url']
        
        # 下载文件内容，添加 verify=False 跳过SSL证书验证
        file_response = requests.get(file_url, verify=False)
        file_response.raise_for_status()
        
        # 转换Markdown为HTML
        md_content = file_response.text
        html_content = markdown.markdown(md_content)
        
        return jsonify({"status": "success", "content": html_content, "filename": md_file['name']})
    except Exception as e:
        app.logger.error(f"获取GitHub更新信息失败: {str(e)}")
        # 提供更详细的错误信息
        error_message = f"获取失败: {str(e)}"
        if "No module named 'markdown'" in str(e):
            error_message = "获取失败: 缺少markdown模块，请安装后重试"
        elif "Connection" in str(e) or "timeout" in str(e).lower():
            error_message = "获取失败: 网络连接错误，请检查网络后重试"
        return jsonify({"status": "error", "message": error_message}), 500


@app.route('/download/<filename>')
@login_required
def download(filename):
    """文件下载路由"""
    if '../' in filename or not re.match(r'^[\w\-. \u4e00-\u9fa5]+$', filename):
        abort(400)
    
    upload_dir = system_config['upload_folder']
    file_path = os.path.join(upload_dir, filename)
    
    # 检查是否为符号链接
    if os.path.islink(file_path):
        abort(400)
    
    if not os.path.isfile(file_path):
        abort(404)
    
    update_metadata(filename, 'download')
    return send_from_directory(upload_dir, filename, as_attachment=True)


@app.route('/preview/<filename>')
@login_required
def preview(filename):
    """文件预览路由"""
    if '../' in filename or not re.match(r'^[\w\-. \u4e00-\u9fa5]+$', filename):
        abort(400)
    
    upload_dir = system_config['upload_folder']
    file_path = os.path.join(upload_dir, filename)
    
    # 检查是否为符号链接
    if os.path.islink(file_path):
        abort(400)
    
    if not os.path.isfile(file_path):
        abort(404)
    
    return send_from_directory(upload_dir, filename)


@app.route('/preview/<zip_filename>/<inner_filename>')
@login_required
def preview_inner_file(zip_filename, inner_filename):
    """预览zip文件内部的文件"""
    from flask import make_response, Response
    import urllib.parse
    import os
    import tempfile
    import zipfile
    import shutil
    import subprocess
    
    # URL解码文件名
    zip_filename = urllib.parse.unquote(zip_filename)
    inner_filename = urllib.parse.unquote(inner_filename)
    
    # 安全检查
    if '../' in zip_filename or '../' in inner_filename:
        abort(400)
    
    # 更宽松的文件名检查，允许更多字符和中文
    if not re.match(r'^[\w\-. \(\)\[\]\{\}│¼╟σ%\u4e00-\u9fa5]+$', zip_filename) or not re.match(r'^[\w\-. \(\)\[\]\{\}│¼╟σ%\u4e00-\u9fa5]+$', inner_filename):
        abort(400)
    
    
    
    # 检查zip文件是否存在
    upload_dir = system_config['upload_folder']
    zip_file_path = os.path.join(upload_dir, zip_filename)
    
    if not os.path.isfile(zip_file_path):
        abort(404)
    
    # 创建临时目录来解压文件
    temp_dir = tempfile.mkdtemp()
    
    try:
        # 解压zip文件
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # 检查内部文件是否存在
        inner_file_path = os.path.join(temp_dir, inner_filename)
        print(f"Initial inner_file_path: {inner_file_path}")
        print(f"inner_filename: {inner_filename}")
        if not os.path.exists(inner_file_path):
            # 尝试在解压的文件中查找匹配的文件
            found = False
            print(f"Looking for file: {inner_filename}")
            for root, dirs, files in os.walk(temp_dir):
                print(f"Files in {root}: {files}")
                for file in files:
                    print(f"Comparing: '{file}' with '{inner_filename}'")
                    if file == inner_filename:
                        inner_file_path = os.path.join(root, file)
                        found = True
                        print(f"Found file at: {inner_file_path}")
                        break
                    # 尝试不同的编码方式匹配文件名
                    else:
                        # 尝试多种编码转换方式
                        encodings_to_try = ['utf-8', 'gbk', 'gb2312', 'latin-1']
                        for enc in encodings_to_try:
                            try:
                                # 尝试用当前编码解码inner_filename
                                decoded_inner = inner_filename.encode('iso-8859-1').decode(enc)
                                # 同时尝试对file变量进行编码转换
                                decoded_file = file.encode('iso-8859-1').decode(enc)
                                if decoded_file == decoded_inner:
                                    inner_file_path = os.path.join(root, file)
                                    found = True
                                    print(f"Found file at: {inner_file_path} after encoding fix with {enc}")
                                    break
                            except (UnicodeEncodeError, UnicodeDecodeError):
                                continue
                        
                        # 如果上述方法都不行，尝试URL解码后比较
                        if not found:
                            import urllib.parse
                            unquoted_file = urllib.parse.unquote(file)
                            if unquoted_file == inner_filename:
                                inner_file_path = os.path.join(root, file)
                                found = True
                                print(f"Found file at: {inner_file_path} after URL decoding")
                        
                        # 如果还是不行，尝试直接比较文件名（去除扩展名）
                        if not found:
                            inner_name_no_ext = os.path.splitext(inner_filename)[0]
                            file_name_no_ext = os.path.splitext(file)[0]
                            if inner_name_no_ext == file_name_no_ext:
                                inner_file_path = os.path.join(root, file)
                                found = True
                                print(f"Found file at: {inner_file_path} after name comparison (without extension)")
                        
                        # 如果仍然未找到，尝试模糊匹配文件名
                        if not found:
                            # 计算文件名相似度
                            import difflib
                            similarity = difflib.SequenceMatcher(None, inner_filename, file).ratio()
                            if similarity > 0.95:  # 95%相似度阈值
                                inner_file_path = os.path.join(root, file)
                                found = True
                                print(f"Found file at: {inner_file_path} after fuzzy matching (similarity: {similarity})")
                if found:
                    break
            
            if not found:
                print("File not found in zip")
                abort(404)
        
        # 检查文件路径是否在临时目录内，防止路径遍历攻击
        if not os.path.abspath(inner_file_path).startswith(os.path.abspath(temp_dir)):
            abort(400)
        
        # 移除FFmpeg转码功能，直接使用原始文件
        # 检查是否为视频文件，设置适当的MIME类型
        if inner_filename.lower().endswith(('.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.webm')):
            # 检查文件是否存在且可读
            if not os.path.exists(inner_file_path) or not os.access(inner_file_path, os.R_OK):
                # 如果文件无法访问，返回错误信息
                abort(404)
        
        # 处理范围请求以支持视频流
        def send_file_partial(path, start=None, length=None):
            """发送文件的一部分以支持范围请求"""
            file_size = os.path.getsize(path)
            if start is None:
                start = 0
            if length is None:
                length = file_size - start
                
            # 确保范围有效
            if start >= file_size:
                start = 0
                length = file_size
                response = make_response()
                response.headers['Content-Range'] = f'bytes */{file_size}'
                response.status_code = 416  # Range Not Satisfiable
                return response
                
            # 确保结束位置不超过文件大小
            end = min(start + length - 1, file_size - 1)
            length = end - start + 1
            
            with open(path, 'rb') as f:
                f.seek(start)
                data = f.read(length)
            
            # 确定MIME类型
            import mimetypes
            mime_type, _ = mimetypes.guess_type(path)
            if inner_filename.lower().endswith('.mp4'):
                mime_type = 'video/mp4'
            elif inner_filename.lower().endswith('.avi'):
                mime_type = 'video/x-msvideo'
            elif inner_filename.lower().endswith('.mov'):
                mime_type = 'video/quicktime'
            elif inner_filename.lower().endswith('.mkv'):
                mime_type = 'video/x-matroska'
            
            response = make_response(data)
            response.headers['Content-Range'] = f'bytes {start}-{end}/{file_size}'
            response.headers['Accept-Ranges'] = 'bytes'
            response.headers['Content-Length'] = length
            response.headers['Content-Type'] = mime_type or 'application/octet-stream'
            response.status_code = 206  # Partial Content
            return response
        
        # 确定MIME类型
        import mimetypes
        mime_type, _ = mimetypes.guess_type(inner_file_path)
        
        # 对于视频和音频文件，确保返回正确的MIME类型
        if inner_filename.lower().endswith('.mp4'):
            mime_type = 'video/mp4'
        elif inner_filename.lower().endswith('.avi'):
            mime_type = 'video/x-msvideo'
        elif inner_filename.lower().endswith('.mov'):
            mime_type = 'video/quicktime'
        elif inner_filename.lower().endswith('.mkv'):
            mime_type = 'video/x-matroska'
        elif inner_filename.lower().endswith('.wmv'):
            mime_type = 'video/x-ms-wmv'
        elif inner_filename.lower().endswith('.flv'):
            mime_type = 'video/x-flv'
        elif inner_filename.lower().endswith('.webm'):
            mime_type = 'video/webm'
        # 音频文件MIME类型
        elif inner_filename.lower().endswith('.mp3'):
            mime_type = 'audio/mpeg'
        elif inner_filename.lower().endswith('.wav'):
            mime_type = 'audio/wav'
        elif inner_filename.lower().endswith('.flac'):
            mime_type = 'audio/flac'
        elif inner_filename.lower().endswith('.aac'):
            mime_type = 'audio/aac'
        elif inner_filename.lower().endswith('.ogg'):
            mime_type = 'audio/ogg'
        elif inner_filename.lower().endswith('.wma'):
            mime_type = 'audio/x-ms-wma'
        
        # 检查是否为范围请求
        range_header = request.headers.get('Range', None)
        if range_header:
            try:
                # 解析范围请求
                range_match = re.match(r'bytes=(\d*)-(\d*)', range_header)
                if range_match:
                    start_str, end_str = range_match.groups()
                    file_size = os.path.getsize(inner_file_path)
                    
                    # 计算起始和结束位置
                    start = int(start_str) if start_str else 0
                    end = int(end_str) if end_str else file_size - 1
                    length = end - start + 1
                    
                    # 发送部分文件
                    return send_file_partial(inner_file_path, start, length)
            except Exception as e:
                print(f"Range request parsing error: {str(e)}")
        
        # 如果不是范围请求，正常发送文件
        # 对于视频和音频文件，使用更直接的方式发送
        if inner_filename.lower().endswith(('.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.webm', 
                                         '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma')):
            # 直接打开文件并流式传输
            file_size = os.path.getsize(inner_file_path)
            response = Response(open(inner_file_path, 'rb'), mimetype=mime_type or 'application/octet-stream')
            response.headers['Content-Length'] = file_size
            response.headers['Accept-Ranges'] = 'bytes'
            response.headers['Content-Disposition'] = f'inline; filename="{inner_filename}"'
            return response
        else:
            response = make_response(send_file(inner_file_path))
            # 设置Accept-Ranges头以支持视频/音频流
            response.headers['Accept-Ranges'] = 'bytes'
            
            if mime_type:
                response.headers['Content-Type'] = mime_type
            
            return response
    except Exception as e:
        # 添加调试日志
        print(f"Error in preview_inner_file: {str(e)}")
        print(f"zip_filename: {zip_filename}")
        print(f"inner_filename: {inner_filename}")
        print(f"zip_file_path: {zip_file_path}")
        print(f"inner_file_path: {inner_file_path}")
        abort(500)
    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir, ignore_errors=True)


#文件详情页面路由
@app.route('/file_detail')
@login_required
def file_detail():
    """文件详情页"""
    filename = request.args.get('file')
    if not filename:
        return redirect('/index')
    
    return render_template('file_detail.html')

@app.route('/api/file_info')
@login_required
def api_file_info():
    """获取文件信息API"""
    filename = request.args.get('filename')
    if not filename:
        return jsonify({"status": "error", "message": "未提供文件名"}), 400
    
    # 获取文件路径
    file_path = os.path.join(system_config['upload_folder'], filename)
    
    if not os.path.exists(file_path):
        return jsonify({"status": "error", "message": "文件不存在"}), 404
    
    # 获取文件信息
    file_info = os.stat(file_path)
    
    # 获取元数据
    metadata = load_metadata()
    file_meta = metadata.get(filename, {})
    
    # 构建响应数据
    response_data = {
        "filename": filename,
        "size": file_info.st_size,
        "created": file_info.st_ctime,
        "modified": file_info.st_mtime,
        "download_count": file_meta.get('download_count', 0)
    }
    
    # 如果是.adofai文件，添加解析信息
    if filename.lower().endswith('.adofai') and 'adofai_info' in file_meta:
        response_data["adofai_info"] = file_meta['adofai_info']
    
    return jsonify(response_data)


# 检查ZIP文件内部媒体文件API
@app.route('/api/check_zip_media')
@login_required
def api_check_zip_media():
    """
    检查ZIP文件内部是否包含可预览的媒体文件（图片、音频、视频）
    
    Returns:
        dict: 包含媒体文件列表的JSON响应
    """
    filename = request.args.get('filename')
    if not filename:
        return jsonify({"status": "error", "message": "未提供文件名"}), 400
    
    # 获取文件路径
    file_path = os.path.join(system_config['upload_folder'], filename)
    
    if not os.path.exists(file_path):
        return jsonify({"status": "error", "message": "文件不存在"}), 404
    
    # 检查是否为ZIP文件
    if not filename.lower().endswith('.zip'):
        return jsonify({"status": "error", "message": "不是ZIP文件"}), 400
    
    try:
        import tempfile
        import zipfile
        import re
        
        temp_dir = tempfile.mkdtemp()
        media_files = {
            "images": [],
            "audios": [],
            "videos": []
        }
        
        try:
            # 解压zip文件
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # 定义媒体文件扩展名
            image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.webp')
            audio_extensions = ('.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma')
            video_extensions = ('.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm')
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_lower = file.lower()
                    # 构建文件URL
                    file_url = f"/preview/{filename}/{file}"
                    
                    # 检查文件类型
                    if file_lower.endswith(image_extensions):
                        media_files["images"].append(file_url)
                    elif file_lower.endswith(audio_extensions):
                        media_files["audios"].append(file_url)
                    elif file_lower.endswith(video_extensions):
                        media_files["videos"].append(file_url)
            
            # 返回媒体文件列表
            return jsonify({
                "status": "success",
                "images": media_files["images"],
                "audios": media_files["audios"],
                "videos": media_files["videos"],
                "count": {
                    "total": len(media_files["images"]) + len(media_files["audios"]) + len(media_files["videos"]),
                    "images": len(media_files["images"]),
                    "audios": len(media_files["audios"]),
                    "videos": len(media_files["videos"])
                }
            })
        finally:
            # 清理临时目录
            import shutil
            shutil.rmtree(temp_dir)
    except Exception as e:
        return jsonify({"status": "error", "message": f"检查ZIP文件失败: {str(e)}"}), 500


# Adofai谱面文件解析API
@app.route('/api/adofai_level_info')
@login_required
def api_adofai_level_info():
    """获取Adofai谱面文件信息API"""
    filename = request.args.get('filename')
    file_type = request.args.get('file_type', 'zip')  # 默认为zip格式
    
    if not filename:
        return jsonify({"status": "error", "message": "未提供文件名"}), 400
    
    # 获取文件路径
    file_path = os.path.join(system_config['upload_folder'], filename)
    
    if not os.path.exists(file_path):
        return jsonify({"status": "error", "message": "文件不存在"}), 404
    
    try:
        # 根据文件类型处理
        if file_type == 'json' and filename.lower().endswith('.adofai'):
            # 直接读取.adofai文件内容
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                import json
                adofai_data = json.load(f)
            
            # 提取pathData并计算步数
            path_data = adofai_data.get('pathData', '')
            steps_count = len(path_data)
            
            # 提取关键信息
            level_info = {
                "song": adofai_data.get("song", "未知"),
                "artist": adofai_data.get("artist", "未知"),
                "author": adofai_data.get("author", "未知"),
                "difficulty": adofai_data.get("difficulty", "未知"),
                "bpm": adofai_data.get("bpm", "未知"),
                "previewImage": adofai_data.get("previewImage", "未知"),
                "previewIcon": adofai_data.get("previewIcon", "未知"),
                "seizureWarning": adofai_data.get("seizureWarning", False),
                "bg": adofai_data.get("bg", "未知"),
                "eggs": adofai_data.get("eggs", []),
                "steps_count": steps_count
            }
            
            # 对于单独的.adofai文件，没有关联的音频、图片和视频文件
            return jsonify({
                "status": "success",
                "level_info": level_info,
                "audio_file": None,
                "image_files": [],
                "video_files": []
            })
        elif file_type == 'zip' and filename.lower().endswith('.zip'):
            # 创建临时目录来解压文件
            import tempfile
            import zipfile
            temp_dir = tempfile.mkdtemp()
            
            try:
                # 解压zip文件
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # 查找.adofai文件
                adofai_file = None
                audio_file = None
                image_files = []
                video_files = []
                
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        if file.lower().endswith('.adofai'):
                            adofai_file = os.path.join(root, file)
                        elif file.lower().endswith(('.ogg', '.mp3', '.wav', '.flac', '.aac')):
                            audio_file = os.path.join(root, file)
                        elif file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')):
                            image_files.append(os.path.join(root, file))
                        elif file.lower().endswith(('.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm')):
                            video_files.append(os.path.join(root, file))
                
                # 获取所有文件和文件夹列表（带类型和大小）
                all_files = []
                all_dirs = []
                all_regular_files = []
                
                for root, dirs, files in os.walk(temp_dir):
                    # 处理当前目录下的文件夹
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        # 计算文件夹大小
                        dir_size = 0
                        for dirpath, dirnames, filenames in os.walk(dir_path):
                            for f in filenames:
                                fp = os.path.join(dirpath, f)
                                if os.path.isfile(fp):
                                    dir_size += os.path.getsize(fp)
                        all_dirs.append({
                            "name": dir_name,
                            "type": "directory",
                            "size": dir_size
                        })
                    # 处理当前目录下的文件
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_size = os.path.getsize(file_path)
                        # 提取文件扩展名
                        ext = os.path.splitext(file)[1].lower() or ""  # 确保ext包含点号
                        if ext.startswith("."):
                            ext = ext[1:]  # 移除点号
                        all_regular_files.append({
                            "name": file,
                            "type": "file",
                            "size": file_size,
                            "extension": ext
                        })
                
                # 首先添加文件夹，然后添加文件，确保文件夹排在前面
                all_files = all_dirs + all_regular_files
                
                if adofai_file:
                    # 读取.adofai文件内容
                    with open(adofai_file, 'r', encoding='utf-8-sig') as f:
                        import json
                        adofai_data = json.load(f)
                    
                    # 提取pathData并计算步数
                    path_data = adofai_data.get('pathData', '')
                    steps_count = len(path_data)
                    
                    # 提取关键信息
                    settings = adofai_data.get("settings", {})
                    level_info = {
                        "song": settings.get("song", "未知"),
                        "artist": settings.get("artist", "未知"),
                        "author": settings.get("author", "未知"),
                        "difficulty": settings.get("difficulty", "未知"),
                        "bpm": settings.get("bpm", "未知"),
                        "previewImage": settings.get("previewImage", "未知"),
                        "previewIcon": settings.get("previewIcon", "未知"),
                        "seizureWarning": settings.get("seizureWarning", False),
                        "bg": settings.get("bg", "未知"),
                        "eggs": adofai_data.get("eggs", []),
                        "steps_count": steps_count
                    }
                    
                    # 获取音频文件名
                    audio_filename = os.path.basename(audio_file) if audio_file else None
                    
                    # 获取图片文件名列表
                    image_filenames = [os.path.basename(img) for img in image_files]
                    
                    # 获取视频文件名列表
                    video_filenames = [os.path.basename(vid) for vid in video_files]
                    
                    return jsonify({
                        "status": "success",
                        "level_info": level_info,
                        "audio_file": audio_filename,
                        "image_files": image_filenames,
                        "video_files": video_filenames,
                        "files": all_files
                    })
                else:
                    # 如果没有找到.adofai文件，仍然返回成功，并包含所有文件列表
                    return jsonify({
                        "status": "success",
                        "level_info": {},
                        "audio_file": None,
                        "image_files": [],
                        "video_files": [],
                        "files": all_files
                    })
            finally:
                # 确保临时目录被清理
                import shutil
                if 'temp_dir' in locals():
                    shutil.rmtree(temp_dir, ignore_errors=True)
        else:
            return jsonify({"status": "error", "message": "不支持的文件类型"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"解析失败: {str(e)}"}), 500


# 启动服务
if __name__ == '__main__':
    print("Registered endpoints(API接口):")
    for rule in app.url_map.iter_rules():
        print(f"{rule.endpoint}: {rule}")
    
    init_system()

    # 密钥管理 - 从环境变量或配置文件获取secret_key
    # 1. 首先尝试从环境变量获取
    secret_key = os.environ.get('FLASK_SECRET_KEY')

    # 2. 如果环境变量没有，则尝试从系统配置获取
    if not secret_key and 'secret_key' in system_config and system_config['secret_key']:
        secret_key = system_config['secret_key']

    # 3. 如果都没有，则生成一个随机密钥
    import secrets
    if not secret_key:
        secret_key = secrets.token_hex(32)  # 生成64位随机十六进制字符串
        print(f"生成随机密钥: {secret_key}")
        # 将生成的密钥保存到配置中，以便下次使用
        system_config['secret_key'] = secret_key
        save_config()

    # 设置Flask应用的secret_key
    app.secret_key = secret_key

    os.makedirs(system_config['upload_folder'], exist_ok=True)
    os.chmod(system_config['upload_folder'], 0o777)  # 确保可写
    
    print("服务已启动")
    print(f"应用名称: {system_config['app_name']} {system_config['app_version']}")
    print(f"上传目录: {system_config['upload_folder']}")
    print(f"总空间上限: {convert_size(system_config['max_total_size'] * 1024 * 1024)}")
    print(f"服务启动时间: {SERVICE_START_TIME}")
    print("\n访问地址: http://localhost:" + str(system_config['port']) + "/")
    print("管理页面: http://localhost:" + str(system_config['port']) + "/admin")
        # 检查更新
    current_version = system_config['app_version']
    update_info = check_for_updates(current_version)
    if update_info:
        print(f"\n\033[92m发现新版本!\033[0m 当前版本: {update_info['current_version']}, 最新版本: {update_info['latest_version']}")
        print(f"下载链接: {update_info['download_url']}")
        print("请访问链接下载并更新到最新版本。\n")
    else:
        print("\n当前已是最新版本。\n")

    app.run(host='::', port=system_config['port'], debug=True, threaded=True)
