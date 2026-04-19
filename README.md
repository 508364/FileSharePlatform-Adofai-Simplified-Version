# 文件共享平台 (Adofai用户注册版)

## 项目概述

这是一个基于Flask的文件共享平台，专为Adofai玩家设计，提供文件上传、下载、管理功能，以及系统资源监控、文件预览等辅助功能。

**当前版本**：v2.0

---

## 目录

- [核心功能](#核心功能)
- [安装与配置](#安装与配置)
- [使用方法](#使用方法)
- [文件结构](#文件结构)
- [插件系统](#插件系统)
- [语言管理](#语言管理)
- [安全注意事项](#安全注意事项)
- [PyOxidizer全平台交叉编译](#pyoxidizer全平台交叉编译)
- [常见问题](#常见问题)

---

## 核心功能

### 1. 用户管理
- 用户注册与登录系统
- 会话管理与安全验证
- 管理员账户系统

### 2. 文件管理
- 文件上传与下载
- 文件预览功能（支持多种格式，包括视频、音频、图片）
- ZIP文件内部文件预览
- 文件元数据管理

### 3. 特殊功能
- Adofai谱面文件解析与预览
- 系统资源监控
- 版本检查与更新通知
- 配置文件管理

### 4. 安全特性
- 密码哈希存储
- 文件访问控制
- 管理员权限验证
- 防CSRF攻击

---

## 安装与配置

### 前提条件
- Python 3.8+
- pip包管理工具

### 安装步骤

1. **克隆或下载项目到本地**

2. **安装依赖包**
```bash
pip install -r requirements.txt
```

3. **启动服务**
```bash
python server.py
```

服务启动后，可以通过以下地址访问：
- 主页面: http://localhost:5001/
- 管理页面: http://localhost:5001/admin

### 配置项说明

配置文件 `fileshare_config.ini` 包含以下配置项：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `app_name` | 应用名称 | 文件共享平台 |
| `app_version` | 应用版本 | 2.0 |
| `max_file_size` | 单个文件最大大小(MB) | 100 |
| `max_total_size` | 总存储空间大小(MB) | 1024 |
| `upload_folder` | 文件上传目录 | uploads |
| `user_login_enabled` | 是否启用用户登录 | true |
| `port` | 服务端口 | 5001 |
| `host` | 绑定地址 | 0.0.0.0 |
| `ipv6_enabled` | 是否启用IPv6 | false |
| `language` | 默认语言 | zh |
| `network_interface` | 网络接口 | auto |
| `debug` | 调试模式 | false |
| `token_expiry` | Token有效期(秒) | 3600 |
| `enable_client_ip_tracking` | 客户端IP追踪 | false |

---

## 使用方法

### 用户操作

1. 在登录页面输入用户名和密码进行登录
2. 登录成功后可上传、下载和管理文件
3. 点击文件可查看详细信息和预览内容

### 管理员操作

1. 访问管理页面进行管理员登录
2. 登录后可管理所有用户上传的文件
3. 可查看系统资源使用情况

**默认管理员账户**：用户名 `bata`，密码 `123456`

### API接口

系统提供RESTful API接口，主要包括：

#### 认证相关
- `POST /api/login` - 用户登录
- `POST /api/logout` - 用户登出
- `GET /api/user/token_info` - 获取用户Token信息

#### 文件管理
- `GET /api/files` - 获取文件列表
- `POST /api/upload` - 上传文件
- `GET /api/download/<filename>` - 下载文件
- `DELETE /api/delete/<filename>` - 删除文件

#### 系统管理
- `GET /api/system/info` - 获取系统信息
- `GET /api/system/stats` - 获取系统统计
- `GET /api/system/config` - 获取系统配置
- `POST /api/update_config` - 更新系统配置
- `GET /api/check_config_file` - 检查配置文件

#### 语言管理
- `GET /api/languages` - 获取所有可用语言
- `GET /api/lang/<lang_code>` - 获取特定语言文件
- `POST /api/lang/<lang_code>` - 更新语言文件
- `POST /api/lang/<lang_code>/create` - 创建新语言
- `DELETE /api/lang/<lang_code>` - 删除语言

---

## 文件结构

```
├── files_metadata.json      # 文件元数据存储
├── fileshare_config.ini     # 系统配置文件
├── fileshare.spec           # PyInstaller配置文件
├── key/                     # 密钥存储目录
│   ├── public_key.key      # 公钥
│   └── private_key.key     # 私钥
├── lang/                    # 语言文件目录（自动生成）
│   ├── zh.json             # 中文语言包
│   └── en.json             # 英文语言包
├── list/                    # 配置列表目录
│   └── file_extensions.json # 文件扩展名配置
├── plugin/                  # 插件目录（自动生成）
│   ├── extensions/         # 插件扩展
│   ├── config/             # 插件配置
│   └── api/                # 插件API
├── requirements.txt         # 项目依赖
├── server.py               # 主程序文件
├── init_app.py             # 应用程序初始化脚本
├── rsa_key_generator.py    # RSA密钥生成器
├── static/                 # 静态资源目录
│   ├── css/               # 样式文件
│   ├── js/                # JavaScript文件
│   └── favicon.ico        # 网站图标
├── templates/              # HTML模板目录
├── uploads/                # 文件上传目录（自动生成）
└── user/                   # 用户数据目录（自动生成）
    └── user.json           # 用户数据
```

---

## 插件系统

### 插件目录结构

```
plugin/
├── extensions/             # 插件扩展目录
│   └── <plugin_name>/
│       ├── manifest.json   # 插件清单
│       ├── plugin.py       # 插件主文件
│       └── (其他插件文件)
├── config/                 # 插件配置目录
│   └── <plugin_name>/
│       └── settings.json    # 插件设置
└── api/                    # 插件API目录
    └── api.json            # 插件API配置
```

### 插件manifest.json格式

```json
{
  "name": "plugin_name",
  "version": "1.0.0",
  "author": "Author Name",
  "description": "Plugin description",
  "dependencies": [],
  "permissions": ["file_access", "upload"]
}
```

### 示例插件

项目包含一个示例插件 `example_plugin`，位于 `plugin/extensions/example_plugin/` 目录。

---

## 语言管理

### 语言文件自动生成

程序启动时会自动创建 `lang/` 目录并生成默认的语言文件：
- `zh.json` - 中文语言包
- `en.json` - 英文语言包

### 语言管理API

系统提供了以下API端点用于语言管理：

| 方法 | 端点 | 说明 |
|------|------|------|
| GET | `/api/languages` | 获取所有可用语言列表 |
| GET | `/api/lang/<lang_code>` | 获取特定语言的翻译文件 |
| POST | `/api/lang/<lang_code>` | 更新特定语言的翻译文件 |
| POST | `/api/lang/<lang_code>/create` | 创建新的语言文件 |
| DELETE | `/api/lang/<lang_code>` | 删除语言文件 |

### 创建自定义语言

**通过API创建：**
```bash
curl -X POST http://localhost:5001/api/lang/ja/create \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: your-admin-token" \
  -d '{
    "name": "日本語",
    "flag": "🇯🇵",
    "translations": {
      "common": {
        "login": "ログイン",
        "logout": "ログアウト"
      }
    }
  }'
```

### 语言文件格式

```json
{
  "name": "中文",
  "flag": "🇨🇳",
  "translations": {
    "common": {
      "login": "登录",
      "logout": "退出"
    },
    "nav": {
      "home": "首页",
      "files": "文件"
    }
  }
}
```

---

## 安全注意事项

1. **修改默认密钥**：建议在生产环境中修改默认的 `secret_key`
2. **保护密钥文件**：密钥文件包含敏感信息，请妥善保管
3. **定期备份**：定期备份重要文件和数据库
4. **设置权限**：注意设置适当的文件权限
5. **反向代理**：建议在反向代理后部署以增强安全性
6. **默认密码**：首次部署后请立即修改默认管理员密码

---

## PyOxidizer全平台交叉编译

本项目支持使用PyOxidizer进行全平台全架构交叉编译。

### 支持的平台和架构

| 平台 | 架构 | 说明 |
|------|------|------|
| Windows | x86_64 | Windows 64位系统 |
| Linux | x86_64 | Linux 64位系统 |
| Linux | aarch64 | ARM64系统（如树莓派） |
| macOS | x86_64 | Intel Mac |
| macOS | aarch64 | Apple Silicon Mac |

### 前置条件

#### 1. 安装Rust

**Windows:**
```powershell
winget install Rustlang.Rustup
```

**WSL/Linux/macOS:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

#### 2. 安装交叉编译工具链

**WSL (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install -y build-essential cmake gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```

**macOS:**
```bash
xcode-select --install
brew install FiloSottile/musl-cross/musl-cross
```

#### 3. 安装PyOxidizer

```bash
cargo install pyoxidizer
```

### 构建步骤

#### 1. 验证环境
```bash
python scripts/pre_build.py
```

#### 2. 构建所有平台
```bash
pyoxidizer build --release
```

#### 3. 构建特定平台
```bash
# Windows x86_64
pyoxidizer build --target-triple x86_64-pc-windows-gnu --release

# Linux x86_64
pyoxidizer build --target-triple x86_64-unknown-linux-gnu --release

# Linux aarch64
pyoxidizer build --target-triple aarch64-unknown-linux-gnu --release

# macOS x86_64
pyoxidizer build --target-triple x86_64-apple-darwin --release

# macOS aarch64
pyoxidizer build --target-triple aarch64-apple-darwin --release
```

#### 4. 处理构建产物
```bash
python scripts/post_build.py
```

### 打包文件说明

**必须打包的文件：**
- `server.py` - 主服务器程序
- `init_app.py` - 应用程序初始化脚本
- `rsa_key_generator.py` - RSA密钥生成器
- `requirements.txt` - Python依赖列表
- `static/**` - 静态文件目录
- `templates/**` - HTML模板目录

**不打包的文件（自动生成）：**
- `uploads/**` - 用户上传文件目录
- `user/**` - 用户数据目录
- `list/**` - 文件扩展名配置目录
- `key/**` - 密钥存储目录
- `lang/**` - 语言文件目录
- `plugin/**` - 插件目录
- `fileshare_config.ini` - 配置文件
- `files_metadata.json` - 文件元数据
- `tokens.pkl` - Token存储文件
- `theme_mode.json` - 主题模式配置

### 构建产物

产物目录：
- `build/windows/x86_64/`
- `build/linux/x86_64/`
- `build/linux/aarch64/`
- `build/macos/x86_64/`
- `build/macos/aarch64/`

分发包：
- `dist/file-share-platform-windows-x86_64.zip`
- `dist/file-share-platform-linux-x86_64.tar.gz`
- `dist/file-share-platform-linux-aarch64.tar.gz`
- `dist/file-share-platform-macos-x86_64.tar.gz`
- `dist/file-share-platform-macos-aarch64.tar.gz`

### 首次运行说明

当用户首次运行打包后的程序时，程序会自动：

1. **创建必要的目录**：uploads/、user/、list/、key/、lang/、plugin/
2. **生成默认配置文件**：fileshare_config.ini、user.json、file_extensions.json
3. **生成RSA密钥对**：公钥和私钥
4. **生成默认语言文件**：zh.json和en.json

### WSL交叉编译详细步骤

1. **在Windows上安装WSL**
```powershell
wsl --install
```

2. **在WSL中设置交叉编译环境**
```bash
wsl -d Ubuntu
sudo apt update
sudo apt install -y build-essential cmake gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
cargo install pyoxidizer
```

3. **在WSL中构建Linux目标**
```bash
git clone <repository-url>
cd <project-directory>
python scripts/pre_build.py
pyoxidizer build --target-triple x86_64-unknown-linux-gnu --release
pyoxidizer build --target-triple aarch64-unknown-linux-gnu --release
python scripts/post_build.py
```

---

## 常见问题

### 1. 端口被占用

**解决方法**：
- 修改 `fileshare_config.ini` 中的 `port` 配置项
- 或查找并关闭占用端口的进程

### 2. 无法上传大文件

**解决方法**：
- 检查 `max_file_size` 配置项
- 检查Web服务器或反向代理的上传大小限制

### 3. 打包失败，提示缺少依赖项

**解决方法**：
- 确保已安装所有依赖：`pip install -r requirements.txt`
- 检查PyInstaller配置文件中的`hiddenimports`列表

### 4. PyOxidizer编译超时

**解决方法**：
- PyOxidizer首次编译需要较长时间（15-30分钟）
- 确保网络连接正常

### 5. 交叉编译工具链错误

**解决方法**：
- 确保已正确安装对应平台的交叉编译工具链
- 对于ARM64目标，需要 `gcc-aarch64-linux-gnu`

### 6. 语言文件不生效

**解决方法**：
- 确保 `lang/` 目录存在且包含语言文件
- 检查语言文件格式是否正确（JSON格式）
- 重启服务器使更改生效

### 7. 插件无法加载

**解决方法**：
- 检查插件目录结构是否正确
- 检查 `manifest.json` 格式是否正确
- 查看服务器日志获取详细错误信息

---

## 版本历史

- **v2.0** - 当前版本
  - 新增插件系统
  - 新增多语言支持
  - 新增PyOxidizer全平台交叉编译支持
  - 优化UI和用户体验
  - 修复多个已知问题

- **v1.2** - 初始版本

---

## 许可证

保留所有权利。

---

**最后更新日期**：2026-04-17
**版本**：2.0
