#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件共享平台初始化脚本

该脚本用于在程序启动时初始化必要的目录和配置文件
"""

import os
import sys
import json
import shutil

# 处理PyInstaller打包后的路径问题
def get_base_path():
    """获取程序的基础路径，处理PyInstaller打包后的情况"""
    if getattr(sys, 'frozen', False):
        # 如果是PyInstaller打包后的可执行文件
        base_path = os.path.dirname(sys.executable)
    else:
        # 否则使用当前脚本所在目录
        base_path = os.path.dirname(os.path.abspath(__file__))
    return base_path

# 获取基础路径
BASE_PATH = get_base_path()

# 配置文件和目录
CONFIG_FILE = os.path.join(BASE_PATH, 'fileshare_config.ini')
USERS_FILE = os.path.join(BASE_PATH, 'user', 'user.json')
FILES_METADATA = os.path.join(BASE_PATH, 'files_metadata.json')
UPLOADS_DIR = os.path.join(BASE_PATH, 'uploads')
USER_DIR = os.path.join(BASE_PATH, 'user')
LIST_DIR = os.path.join(BASE_PATH, 'list')
FILE_EXTENSIONS_CONFIG = os.path.join(BASE_PATH, 'list', 'file_extensions.json')
STATIC_DIR = os.path.join(BASE_PATH, 'static')
TEMPLATES_DIR = os.path.join(BASE_PATH, 'templates')
KEY_DIR = os.path.join(BASE_PATH, 'key')

# 默认配置
DEFAULT_CONFIG = {
    "app_name": "文件共享平台",
    "app_version": "2.0",
    "max_file_size": 100,  # MB
    "max_total_size": 1024,  # MB
    "upload_folder": "uploads",
    "user_login_enabled": True,
    "port": 5001,
    "language": "zh",
    "network_interface": "auto",
    "secret_key": "",  # 密钥配置，为空时会自动生成
    "token_expiry": 3600  # Token有效期为1小时（3600秒）
}

# 默认用户配置
DEFAULT_USERS = {
    "users": [
        {
            "username": "bata",
            "password": "123456",
            "qq": ""
        }
    ]
}

# 默认文件扩展名配置
DEFAULT_FILE_EXTENSIONS = {
    "enabled": False,
    "mode": "whitelist",
    "extensions": [
        ".zip",
        ".adofai",
        ".exe"
    ]
}

# 默认文件元数据
DEFAULT_METADATA = {
    "files": []
}

def init_directories():
    """初始化必要的目录"""
    # 只创建动态目录，static和templates由PyInstaller打包，不需要创建
    directories = [
        UPLOADS_DIR,
        USER_DIR,
        LIST_DIR,
        KEY_DIR
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"创建目录: {directory}")
        else:
            print(f"目录已存在: {directory}")

def init_config_file():
    """初始化配置文件"""
    # 检查是否存在旧的配置文件
    old_config_file = os.path.join(BASE_PATH, 'fileshare_config.json')
    if os.path.exists(old_config_file) and not os.path.exists(CONFIG_FILE):
        # 重命名旧配置文件为新文件名
        try:
            os.rename(old_config_file, CONFIG_FILE)
            print(f"已将配置文件重命名: {old_config_file} -> {CONFIG_FILE}")
        except Exception as e:
            print(f"重命名配置文件失败: {str(e)}")
    
    # 检查新配置文件是否存在
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_CONFIG, f, ensure_ascii=False, indent=4)
        print(f"创建配置文件: {CONFIG_FILE}")
    else:
        print(f"配置文件已存在: {CONFIG_FILE}")

def init_users_file():
    """初始化用户文件"""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_USERS, f, ensure_ascii=False, indent=4)
        print(f"创建用户文件: {USERS_FILE}")
    else:
        print(f"用户文件已存在: {USERS_FILE}")

def init_file_extensions():
    """初始化文件扩展名配置"""
    if not os.path.exists(FILE_EXTENSIONS_CONFIG):
        with open(FILE_EXTENSIONS_CONFIG, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_FILE_EXTENSIONS, f, ensure_ascii=False, indent=4)
        print(f"创建文件扩展名配置: {FILE_EXTENSIONS_CONFIG}")
    else:
        print(f"文件扩展名配置已存在: {FILE_EXTENSIONS_CONFIG}")

def init_files_metadata():
    """初始化文件元数据"""
    if not os.path.exists(FILES_METADATA):
        with open(FILES_METADATA, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_METADATA, f, ensure_ascii=False, indent=4)
        print(f"创建文件元数据: {FILES_METADATA}")
    else:
        print(f"文件元数据已存在: {FILES_METADATA}")

def main():
    """主函数，初始化所有必要的文件和目录"""
    print("开始初始化文件共享平台...")
    
    # 初始化目录
    init_directories()
    
    # 初始化配置文件
    init_config_file()
    
    # 初始化用户文件
    init_users_file()
    
    # 初始化文件扩展名配置
    init_file_extensions()
    
    # 初始化文件元数据
    init_files_metadata()
    
    print("初始化完成!")

if __name__ == "__main__":
    main()
