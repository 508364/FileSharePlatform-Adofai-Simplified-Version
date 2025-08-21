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


# ==============================================
# 第三方库导入
# ==============================================
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from flask import Flask, render_template, send_from_directory, send_file, request, jsonify, abort, session, redirect, url_for, flash


# ==============================================
# 全局变量与配置
# ==============================================

# Flask应用实例
app = Flask(__name__)
app.secret_key = os.urandom(24)  # 添加密钥用于session管理

# 线程锁 - 用于确保文件操作的线程安全
upload_lock = threading.Lock()

# GitHub镜像克隆队列及相关状态管理
github_clone_queue = queue.Queue()
github_clone_tasks = {}
github_clone_lock = threading.Lock()
active_cloners = {}  # 当前活跃的克隆任务

# 离线下载任务存储
OFFLINE_TASKS = {}
OFFLINE_QUEUE = queue.Queue()

# 系统配置默认值
DEFAULT_CONFIG = {
    'upload_folder': 'uploads',        # 文件上传目录
    'max_file_size': 100,              # 单个文件最大大小(MB)
    'max_total_size': 1024,            # 总存储空间大小(MB)
    'app_name': '文件共享平台',         # 应用名称
    'app_version': '1.1',              # 应用版本
    'admin_user': 'admin',             # 管理员用户名
    'admin_password': 'admin@123',     # 管理员密码
    'port': 5000,                      # 服务端口
    'network_interface': 'auto',       # 网络接口配置
}

# 系统当前配置 - 初始化为默认配置的副本
system_config = DEFAULT_CONFIG.copy()

# ===============================================
# 更新检查功能
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
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)
        
        response = session.get(api_url, timeout=10)
        response.raise_for_status()
        
        # 解析响应
        release_info = response.json()
        latest_version = release_info.get('tag_name', '').replace('FileSharePlatform-v', '')
        
        # 版本比较
        if latest_version and latest_version > current_version:
            # 构建下载链接
            download_url = f'https://github.com/{owner}/{repo}/releases/tag/FileSharePlatform-v{latest_version}'
            
            return {
                'current_version': current_version,
                'latest_version': latest_version,
                'download_url': download_url,
                'release_notes': release_info.get('body', '')
            }
        return None
    except Exception as e:
        print(f"检查更新失败: {e}")
        return None

# 配置与元数据文件路径
CONFIG_FILE = 'fileshare_config.json'   # 系统配置文件
METADATA_FILE = 'files_metadata.json'   # 文件元数据存储文件

# 服务启动时间
SERVICE_START_TIME = datetime.now()

# ==============================================
# 系统初始化与配置管理
# ==============================================

def init_system():
    """
    初始化系统环境
    
    创建必要目录、加载保存配置并确保元数据文件有效
    """
    
    # 创建必要目录 - 使用绝对路径确保打包后能正确访问
    # 确保upload_folder是绝对路径
    if not os.path.isabs(system_config['upload_folder']):
        system_config['upload_folder'] = os.path.abspath(system_config['upload_folder'])
    
    if not os.path.exists(system_config['upload_folder']):
        os.makedirs(system_config['upload_folder'])
    
    # 加载保存的配置
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
    
    # 确保元数据文件有效
    if not os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'w', encoding='utf-8-sig') as f:
            json.dump({}, f)
    
    # 修复空文件问题
    elif os.path.getsize(METADATA_FILE) == 0:
        with open(METADATA_FILE, 'w', encoding='utf-8-sig') as f:
            json.dump({}, f)
    
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
    return encrypt_password(password) == encrypted_password

def save_config():
    """保存当前配置到配置文件"""
    try:
        # 创建配置副本以避免修改原始配置
        config_to_save = system_config.copy()
        
        # 如果存在密码字段，对其进行加密处理
        if 'admin_password' in config_to_save:
            config_to_save['admin_password'] = encrypt_password(config_to_save['admin_password'])
        
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


def update_metadata(filename, action='upload'):
    """
    更新文件元数据
    
    Args:
        filename (str): 文件名
        action (str): 操作类型,可选值: 'upload' | 'download' | 'delete'
    
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
            'download_count': 0
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
        if '../' in filename or not re.match(r'^[\w\-. ]+$', filename):
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
        # 返回模拟数据
        return { 
            'cpu_percent': '获取系统资源失败',
            'mem_percent': '获取系统资源失',
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
            
        return jsonify({"status": "error", "message": "未授权访问"}), 403
    
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
            'actions_count': len(data.get('actions', []))
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
@app.route('/admin')
def admin():
    """管理员控制面板页面"""
    # 检查管理员登录状态
    if 'admin_token' not in session:
        # 重定向到客户端登录页面
        return redirect('/admin/login')
    
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
    
    return render_template(
        'admin.html',
        disk_space=disk_space,
        files=files,
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
        
    )


@app.route('/admin/login', methods=['GET'], endpoint='admin_login_get')
def admin_login_get():
    """管理员登录页面"""
    return render_template('admin_login.html')


@app.route('/admin/login', methods=['POST'], endpoint='admin_login_post')
def admin_login_post():
    """管理员登录API"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    print(f"收到管理员登录请求: 用户名={username}")
    
    
    # 验证用户名和密码(使用加密验证)
    if username == system_config['admin_user'] and verify_password_encrypted(password, system_config['admin_password']):
        session_token = os.urandom(24).hex()
        session['admin_token'] = session_token
        return jsonify({"status": "success", "token": session_token})
    
    return jsonify({"status": "error", "message": "无效凭据"}), 401


@app.route('/admin/change_password', methods=['POST'], endpoint='admin_change_password')
def admin_change_password():
    # 获取表单数据
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # 验证当前密码(使用加密验证)
    if not verify_password_encrypted(current_password, system_config['admin_password']):
        flash('当前密码不正确', 'error')
        return redirect(url_for('admin'))
    
    # 验证新密码匹配
    if new_password != confirm_password:
        flash('新密码不匹配', 'error')
        return redirect(url_for('admin'))
    
    # 更新密码(保存哈希值)
    system_config['admin_password'] = new_password
    save_config()
    
    flash('密码已成功更新', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/logout')
def admin_logout():
    """管理员登出"""
    session.pop('admin_token', None)
    return redirect('/admin/login')


# 文件操作API
@app.route('/api/files')
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


@app.route('/api/upload', methods=['POST'])
def upload():
    """文件上传API"""
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "未选择文件"})
    
    file = request.files['file']
    
    # 验证文件名
    if not file.filename or '.' not in file.filename:
        return jsonify({"status": "error", "message": "无效的文件名"})
    
    # 允许上传.zip和.adofai文件
    allowed_extensions = ['.zip', '.adofai']
    if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
        return jsonify({"status": "error", "message": "只允许上传.zip和.adofai文件"})
    
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
        
        # 安全保存文件
        filename = secure_filename(file.filename)
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
            update_metadata(filename, 'upload')
            return jsonify({"status": "success", "filename": filename})
        except Exception as e:
            return jsonify({"status": "error", "message": f"保存失败: {str(e)}"})


@app.route('/api/delete_file', methods=['POST'])
@require_admin_token
def api_delete_file():
    """删除文件API"""
    try:
        # 从JSON数据获取文件名
        data = request.get_json()
        filename = data.get('filename')
        
        if not filename:
            return jsonify({"status": "error", "message": "文件名不能为空"}), 400
        
        # 安全检查，防止目录遍历攻击
        if '../' in filename or not re.match(r'^[\w\-. ]+$', filename):
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
            os.remove(file_path)
            # 更新元数据
            update_metadata(filename, 'delete')
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


# 页面路由
@app.route('/')
def index():
    """文件下载中心首页"""
    disk = get_disk_usage()
    files = get_file_list()
    
    return render_template(
        'index.html',
        files=files,
        app_name=system_config['app_name'],
        total_space=convert_size(disk['upload_total']),
        used_space=convert_size(disk['upload_used']),
        free_space=convert_size(disk['available']),
        max_file_size=system_config['max_file_size'],
        usage_percent=disk['usage_percent']
    )


@app.route('/download/<filename>')
def download(filename):
    """文件下载路由"""
    if '../' in filename or not re.match(r'^[\w\-. ]+$', filename):
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
def preview(filename):
    """文件预览路由"""
    if '../' in filename or not re.match(r'^[\w\-. ]+$', filename):
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
def preview_inner_file(zip_filename, inner_filename):
    """预览zip文件内部的文件"""
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
    
    # 更宽松的文件名检查，允许更多字符
    if not re.match(r'^[\w\-. \(\)\[\]\{\}│¼╟σ%]+$', zip_filename) or not re.match(r'^[\w\-. \(\)\[\]\{\}│¼╟σ%]+$', inner_filename):
        abort(400)
    
    # URL解码文件名
    import urllib.parse
    zip_filename = urllib.parse.unquote(zip_filename)
    inner_filename = urllib.parse.unquote(inner_filename)
    
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
            if start is None and length is None:
                return send_file(path)
            
            file_size = os.path.getsize(path)
            if start is None:
                start = 0
            if length is None:
                length = file_size - start
            
            with open(path, 'rb') as f:
                f.seek(start)
                data = f.read(length)
            
            response = make_response(data)
            response.headers['Content-Range'] = f'bytes {start}-{start + length - 1}/{file_size}'
            response.headers['Accept-Ranges'] = 'bytes'
            response.headers['Content-Length'] = length
            response.status_code = 206  # Partial Content
            return response
        
        # 检查是否为范围请求
        range_header = request.headers.get('Range', None)
        if range_header:
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
        
        # 如果不是范围请求，正常发送文件
        response = make_response(send_file(inner_file_path))
        
        # 设置Accept-Ranges头以支持视频流
        response.headers['Accept-Ranges'] = 'bytes'
        
        # 根据文件扩展名设置Content-Type
        import mimetypes
        mime_type, _ = mimetypes.guess_type(inner_file_path)
        
        # 对于视频文件，确保返回正确的MIME类型
        if inner_filename.lower().endswith(('.mp4', '.avi', '.mov', '.mkv')):
            if not mime_type or not mime_type.startswith('video/'):
                # 如果mimetypes无法正确识别，手动设置常见的视频MIME类型
                if inner_filename.lower().endswith('.mp4'):
                    mime_type = 'video/mp4'
                elif inner_filename.lower().endswith('.avi'):
                    mime_type = 'video/x-msvideo'
                elif inner_filename.lower().endswith('.mov'):
                    mime_type = 'video/quicktime'
                elif inner_filename.lower().endswith('.mkv'):
                    mime_type = 'video/x-matroska'
        
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
def file_detail():
    """文件详情页"""
    filename = request.args.get('file')
    if not filename:
        return redirect('/index')
    
    return render_template('file_detail.html')

@app.route('/api/file_info')
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


# Adofai谱面文件解析API
@app.route('/api/adofai_level_info')
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
                "eggs": adofai_data.get("eggs", [])
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
                        if file.endswith('.adofai'):
                            adofai_file = os.path.join(root, file)
                        elif file.endswith(('.ogg', '.mp3', '.wav')):
                            audio_file = os.path.join(root, file)
                        elif file.endswith(('.png', '.jpg', '.jpeg')):
                            image_files.append(os.path.join(root, file))
                        elif file.endswith(('.mp4', '.avi', '.mkv')):
                            video_files.append(os.path.join(root, file))
                
                # 检查必需文件
                if not adofai_file:
                    return jsonify({"status": "error", "message": "未找到.adofai文件"}), 400
                
                # 读取.adofai文件内容
                with open(adofai_file, 'r', encoding='utf-8-sig') as f:
                    import json
                    adofai_data = json.load(f)
                
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
                    "eggs": adofai_data.get("eggs", [])
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
                    "video_files": video_filenames
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

    
    os.makedirs(system_config['upload_folder'], exist_ok=True)
    os.chmod(system_config['upload_folder'], 0o777)  # 确保可写
    
    print("服务已启动")
    print(f"应用名称: {system_config['app_name']} v{system_config['app_version']}")
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

    app.run(host='0.0.0.0', port=system_config['port'], debug=True)
