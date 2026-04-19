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
LANG_DIR = os.path.join(BASE_PATH, 'lang')

# 默认配置
DEFAULT_CONFIG = {
    "app_name": "文件共享平台",
    "app_version": "2.0",
    "max_file_size": 100,  # MB
    "max_total_size": 1024,  # MB
    "upload_folder": "uploads",
    "user_login_enabled": True,
    "port": 5001,
    "host": "0.0.0.0",  # 绑定到所有网络接口，支持FRP映射
    "ipv6_enabled": False,  # 是否启用IPv6双栈绑定
    "language": "zh",
    "network_interface": "auto",
    "debug": False,  # 调试模式
    "secret_key": "",  # 密钥配置，为空时会自动生成
    "token_expiry": 3600,  # Token有效期为1小时（3600秒）
    # 插件API设置
    "plugin_file_access_enabled": True,  # 插件文件访问功能
    "plugin_upload_enabled": True,       # 插件上传文件功能
    "plugin_http_enabled": True,        # 插件外网访问功能
    # 客户端IP追踪
    "enable_client_ip_tracking": False   # 是否启用客户端IP追踪
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

# 默认语言文件配置
DEFAULT_LANGUAGES = {
    "zh": {
        "name": "中文",
        "flag": "🇨🇳",
        "translations": {
            "common": {
                "login": "登录",
                "logout": "退出",
                "register": "注册",
                "upload": "上传",
                "download": "下载",
                "delete": "删除",
                "cancel": "取消",
                "confirm": "确认",
                "save": "保存",
                "edit": "编辑",
                "search": "搜索",
                "filter": "筛选",
                "refresh": "刷新",
                "loading": "加载中...",
                "success": "成功",
                "error": "错误",
                "warning": "警告",
                "info": "信息"
            },
            "nav": {
                "home": "首页",
                "files": "文件",
                "admin": "管理",
                "settings": "设置",
                "help": "帮助"
            },
            "file": {
                "name": "文件名",
                "size": "大小",
                "type": "类型",
                "date": "日期",
                "uploader": "上传者",
                "downloads": "下载次数",
                "no_files": "暂无文件",
                "upload_success": "上传成功",
                "upload_failed": "上传失败",
                "delete_confirm": "确定要删除这个文件吗？",
                "delete_success": "删除成功",
                "delete_failed": "删除失败"
            },
            "user": {
                "username": "用户名",
                "password": "密码",
                "login_success": "登录成功",
                "login_failed": "登录失败",
                "logout_success": "已退出登录",
                "register_success": "注册成功",
                "register_failed": "注册失败"
            },
            "admin": {
                "dashboard": "控制面板",
                "users": "用户管理",
                "files": "文件管理",
                "settings": "系统设置",
                "logs": "系统日志",
                "plugins": "插件管理"
            }
        }
    },
    "en": {
        "name": "English",
        "flag": "🇺🇸",
        "translations": {
            "common": {
                "login": "Login",
                "logout": "Logout",
                "register": "Register",
                "upload": "Upload",
                "download": "Download",
                "delete": "Delete",
                "cancel": "Cancel",
                "confirm": "Confirm",
                "save": "Save",
                "edit": "Edit",
                "search": "Search",
                "filter": "Filter",
                "refresh": "Refresh",
                "loading": "Loading...",
                "success": "Success",
                "error": "Error",
                "warning": "Warning",
                "info": "Info"
            },
            "nav": {
                "home": "Home",
                "files": "Files",
                "admin": "Admin",
                "settings": "Settings",
                "help": "Help"
            },
            "file": {
                "name": "File Name",
                "size": "Size",
                "type": "Type",
                "date": "Date",
                "uploader": "Uploader",
                "downloads": "Downloads",
                "no_files": "No files",
                "upload_success": "Upload successful",
                "upload_failed": "Upload failed",
                "delete_confirm": "Are you sure you want to delete this file?",
                "delete_success": "Delete successful",
                "delete_failed": "Delete failed"
            },
            "user": {
                "username": "Username",
                "password": "Password",
                "login_success": "Login successful",
                "login_failed": "Login failed",
                "logout_success": "Logged out",
                "register_success": "Registration successful",
                "register_failed": "Registration failed"
            },
            "admin": {
                "dashboard": "Dashboard",
                "users": "User Management",
                "files": "File Management",
                "settings": "System Settings",
                "logs": "System Logs",
                "plugins": "Plugin Management"
            }
        }
    }
}

def init_directories():
    """初始化必要的目录"""
    # 只创建动态目录，static和templates由PyInstaller打包，不需要创建
    directories = [
        UPLOADS_DIR,
        USER_DIR,
        LIST_DIR,
        KEY_DIR,
        LANG_DIR,
        os.path.join(BASE_PATH, 'plugin'),
        os.path.join(BASE_PATH, 'plugin', 'extensions'),
        os.path.join(BASE_PATH, 'plugin', 'config'),
        os.path.join(BASE_PATH, 'plugin', 'api'),
        os.path.join(BASE_PATH, 'uploads', '.plugins')
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"创建目录: {directory}")
        else:
            print(f"目录已存在: {directory}")

def normalize_bool(value, default=False):
    """
    将各种格式的值规范化为布尔值
    支持: true, True, FALSE, False, 1, 0, 'on', 'off' 等
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ('true', '1', 'on', 'yes')
    if isinstance(value, int):
        return value != 0
    return default

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
        # 配置文件已存在，检查是否有缺失的配置项
        print(f"配置文件已存在: {CONFIG_FILE}")
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8-sig') as f:
                existing_config = json.load(f)

            config_updated = False
            missing_keys = []

            # 检查缺失的配置项
            for key in DEFAULT_CONFIG:
                if key not in existing_config:
                    existing_config[key] = DEFAULT_CONFIG[key]
                    missing_keys.append(key)
                    config_updated = True

            # 特殊处理 debug 配置，确保是布尔值
            if 'debug' in existing_config:
                existing_config['debug'] = normalize_bool(existing_config['debug'], default=False)

            # 保存更新后的配置
            if config_updated:
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(existing_config, f, ensure_ascii=False, indent=4)
                print(f"已补充缺失的配置项: {missing_keys}")
        except Exception as e:
            print(f"检查配置文件失败: {str(e)}")

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

def init_language_files():
    """初始化语言文件"""
    # 确保lang目录存在
    if not os.path.exists(LANG_DIR):
        os.makedirs(LANG_DIR)
        print(f"创建语言目录: {LANG_DIR}")
    
    # 为每种默认语言创建文件
    for lang_code, lang_data in DEFAULT_LANGUAGES.items():
        lang_file = os.path.join(LANG_DIR, f"{lang_code}.json")
        
        if not os.path.exists(lang_file):
            # 创建新的语言文件
            with open(lang_file, 'w', encoding='utf-8') as f:
                json.dump(lang_data, f, ensure_ascii=False, indent=4)
            print(f"创建语言文件: {lang_file}")
        else:
            # 语言文件已存在，检查是否需要更新
            try:
                with open(lang_file, 'r', encoding='utf-8') as f:
                    existing_lang = json.load(f)
                
                # 检查是否有缺失的翻译键
                updated = False
                for key, value in lang_data['translations'].items():
                    if key not in existing_lang.get('translations', {}):
                        if 'translations' not in existing_lang:
                            existing_lang['translations'] = {}
                        existing_lang['translations'][key] = value
                        updated = True
                
                # 如果有更新，保存文件
                if updated:
                    with open(lang_file, 'w', encoding='utf-8') as f:
                        json.dump(existing_lang, f, ensure_ascii=False, indent=4)
                    print(f"更新语言文件: {lang_file}")
                else:
                    print(f"语言文件已存在: {lang_file}")
            except Exception as e:
                print(f"检查语言文件失败 {lang_file}: {str(e)}")

def check_missing_services():
    """
    检查缺失的服务和文件
    返回: (missing_services, missing_files) - 缺失的服务列表和缺失的文件列表
    """
    missing_services = []
    missing_files = []

    # 必需的目录/服务
    required_directories = [
        ('uploads', UPLOADS_DIR),
        ('user', USER_DIR),
        ('list', LIST_DIR),
        ('key', KEY_DIR),
        ('plugin', os.path.join(BASE_PATH, 'plugin')),
        ('static', STATIC_DIR),
        ('templates', TEMPLATES_DIR),
    ]

    # 必需的配置文件
    required_files = [
        ('CONFIG_FILE', CONFIG_FILE),
        ('USERS_FILE', USERS_FILE),
        ('FILES_METADATA', FILES_METADATA),
        ('FILE_EXTENSIONS_CONFIG', FILE_EXTENSIONS_CONFIG),
    ]

    # 检查目录
    for service_name, service_path in required_directories:
        if not os.path.exists(service_path):
            missing_services.append((service_name, service_path))

    # 检查文件
    for file_name, file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append((file_name, file_path))

    return missing_services, missing_files

def print_service_check_report():
    """打印服务检查报告"""
    missing_services, missing_files = check_missing_services()

    if not missing_services and not missing_files:
        print("✓ 所有必需的服务和文件都已就绪")
    else:
        if missing_services:
            print("缺失的服务/目录:")
            for service_name, service_path in missing_services:
                print(f"  ✗ {service_name}: {service_path}")

        if missing_files:
            print("缺失的文件:")
            for file_name, file_path in missing_files:
                print(f"  ✗ {file_name}: {file_path}")

    return missing_services, missing_files

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

    # 初始化语言文件
    init_language_files()

    # 打印服务检查报告
    print_service_check_report()

    print("初始化完成!")

if __name__ == "__main__":
    main()
