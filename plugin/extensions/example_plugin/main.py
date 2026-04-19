"""
示例插件 - 入口文件

这个文件是插件系统加载和执行的主要入口点
"""

import json
import os
from datetime import datetime

PLUGIN_NAME = "example_plugin"
PLUGIN_VERSION = "1.0.0"

def get_plugin_info():
    """获取插件信息"""
    return {
        "name": PLUGIN_NAME,
        "version": PLUGIN_VERSION,
        "status": "running"
    }

def get_plugin_api():
    """获取插件提供的API端点"""
    return {
        "/api/plugin/example/info": {
            "method": "GET",
            "handler": "get_info",
            "description": "获取插件信息"
        },
        "/api/plugin/example/status": {
            "method": "GET",
            "handler": "get_status",
            "description": "获取插件运行状态"
        }
    }

def get_info():
    """API处理器：获取插件信息"""
    return {
        "status": "success",
        "data": {
            "name": PLUGIN_NAME,
            "version": PLUGIN_VERSION,
            "loaded_at": datetime.now().isoformat()
        }
    }

def get_status():
    """API处理器：获取插件运行状态"""
    return {
        "status": "success",
        "data": {
            "running": True,
            "uptime": "1小时30分钟",
            "requests_processed": 42
        }
    }

def load_config():
    """加载插件配置"""
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "config",
        PLUGIN_NAME,
        "settings.json"
    )
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_config(config):
    """保存插件配置"""
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "config",
        PLUGIN_NAME,
        "settings.json"
    )
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4, ensure_ascii=False)

def on_enable():
    """插件启用时的回调"""
    print(f"[{PLUGIN_NAME}] 插件已启用")

def on_disable():
    """插件禁用时的回调"""
    print(f"[{PLUGIN_NAME}] 插件已禁用")

def on_config_changed(config):
    """配置更改时的回调"""
    print(f"[{PLUGIN_NAME}] 配置已更新")
    print(f"新配置: {config}")

if __name__ == "__main__":
    print(f"示例插件 v{PLUGIN_VERSION}")
    print(f"插件信息: {get_plugin_info()}")
    print(f"API端点: {get_plugin_api()}")
