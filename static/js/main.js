// 文件共享平台主脚本
// 包含所有非管理页面的共用功能

// 主题切换功能
document.addEventListener('DOMContentLoaded', function() {
    // 主题切换
    const themeToggle = document.getElementById('theme-toggle');
    const savedTheme = localStorage.getItem('theme') || 
                    (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    
    if (themeToggle) {
        // 设置初始主题和图标
        if (savedTheme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
            themeToggle.innerHTML = `<i class="bi bi-sun"></i>`;
        } else {
            document.documentElement.removeAttribute('data-theme');
            themeToggle.innerHTML = `<i class="bi bi-moon"></i>`;
        }
        
        // 添加主题切换事件监听
        themeToggle.addEventListener('click', function() {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            if (currentTheme === 'dark') {
                document.documentElement.removeAttribute('data-theme');
                localStorage.setItem('theme', 'light');
                themeToggle.innerHTML = `<i class="bi bi-moon"></i>`;
            } else {
                document.documentElement.setAttribute('data-theme', 'dark');
                localStorage.setItem('theme', 'dark');
                themeToggle.innerHTML = `<i class="bi bi-sun"></i>`;
            }
        });
    }
    
    // 主题色切换功能
    const themeColorOptions = document.querySelectorAll('.theme-color-option');
    const savedThemeColor = localStorage.getItem('theme-color');
    
    // 应用保存的主题色
    if (savedThemeColor) {
        applyThemeColor(savedThemeColor);
    }
    
    // 为主题色选项添加点击事件
    themeColorOptions.forEach(option => {
        // 为当前选中的主题色添加激活状态
        if (option.dataset.color === savedThemeColor) {
            option.style.borderColor = '#000';
            option.style.transform = 'scale(1.1)';
        }
        
        option.addEventListener('click', function() {
            const color = this.dataset.color;
            applyThemeColor(color);
            localStorage.setItem('theme-color', color);
            
            // 更新激活状态
            themeColorOptions.forEach(opt => {
                opt.style.borderColor = 'transparent';
                opt.style.transform = 'scale(1)';
            });
            this.style.borderColor = '#000';
            this.style.transform = 'scale(1.1)';
        });
    });
    
    // 应用主题色
    function applyThemeColor(color) {
        const root = document.documentElement;
        root.style.setProperty('--primary', color);
        
        // 计算深色主题下的主题色
        const hex = color.replace('#', '');
        const r = parseInt(hex.substring(0, 2), 16);
        const g = parseInt(hex.substring(2, 4), 16);
        const b = parseInt(hex.substring(4, 6), 16);
        
        // 生成深色版本（降低亮度）
        const darkR = Math.max(0, Math.floor(r * 0.75));
        const darkG = Math.max(0, Math.floor(g * 0.75));
        const darkB = Math.max(0, Math.floor(b * 0.75));
        const darkColor = `#${darkR.toString(16).padStart(2, '0')}${darkG.toString(16).padStart(2, '0')}${darkB.toString(16).padStart(2, '0')}`;
        
        root.style.setProperty('--primary-dark', darkColor);
        root.style.setProperty('--secondary', darkColor);
    }
});

// 文件上传功能
let fileUploadInitialized = false;
function initFileUpload() {
    if (fileUploadInitialized) return;
    fileUploadInitialized = true;
    
    const dropArea = document.getElementById('drop-area');
    if (!dropArea) return;
    
    const fileInput = document.getElementById('file-input');
    const browseBtn = document.getElementById('browse-btn');
    const uploadContent = document.getElementById('upload-content');
    const uploadProgress = document.getElementById('upload-progress');
    const uploadProgressBar = document.getElementById('upload-progress-bar');
    const uploadStats = document.getElementById('upload-stats');
    
    if (!fileInput || !browseBtn || !uploadContent || !uploadProgress) return;
    
    // 设置为单文件上传
    fileInput.setAttribute('multiple', 'false');
    
    browseBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFiles);
    
    // 拖拽事件处理
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, preventDefaults, false);
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, highlight, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, unhighlight, false);
    });
    
    function highlight() {
        dropArea.style.borderColor = 'var(--primary)';
        dropArea.style.backgroundColor = 'rgba(67, 97, 238, 0.05)';
    }
    
    function unhighlight() {
        dropArea.style.borderColor = '';
        dropArea.style.backgroundColor = '';
    }
    
    dropArea.addEventListener('drop', handleDrop, false);
    
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        // 只处理第一个文件
        const singleFile = files[0];
        if (singleFile) {
            handleFiles({ target: { files: [singleFile] } });
        }
    }
    
    let isUploading = false;
    
    function handleFiles(e) {
        const files = e.target.files;
        if (files.length === 0 || isUploading) return;
        
        // 只处理第一个文件
        const file = files[0];
        
        // 开始上传
        isUploading = true;
        uploadFile(file);
    }
    
    function uploadFile(file) {
        uploadContent.classList.add('d-none');
        uploadProgress.classList.remove('d-none');
        document.getElementById('upload-filename').innerText = file.name;
        
        const formData = new FormData();
        formData.append('file', file);
        
        const username = document.getElementById('username-display')?.textContent || '{{ username }}';
        formData.append('username', username);
        
        const startTime = Date.now();
        let lastLoaded = 0;
        let lastTime = startTime;
        
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload');
        
        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                uploadProgressBar.style.width = `${percent}%`;
                
                const now = Date.now();
                const timeDiff = (now - lastTime) / 1000;
                
                let speed = 0;
                let remainingTime = 0;
                
                if (timeDiff > 0 || e.loaded === e.total) {
                    if (timeDiff > 0) {
                        const loadedDiff = e.loaded - lastLoaded;
                        speed = Math.round(loadedDiff / timeDiff / 1024);
                        if (speed > 0) {
                            const remainingBytes = e.total - e.loaded;
                            remainingTime = Math.round(remainingBytes / (speed * 1024));
                        }
                    }
                    
                    uploadStats.innerText = `${percent}% • ${speed > 0 ? speed : '0'} KB/s • ${remainingTime > 0 ? remainingTime : '0'}s 剩余`;
                    
                    if (timeDiff > 0.5) {
                        lastLoaded = e.loaded;
                        lastTime = now;
                    }
                }
            }
        });
        
        xhr.addEventListener('load', () => {
            if (xhr.status === 200) {
                uploadStats.innerText = '上传成功！';
                setTimeout(() => {
                    // 上传完成，重置状态
                    isUploading = false;
                    uploadContent.classList.remove('d-none');
                    uploadProgress.classList.add('d-none');
                    uploadProgressBar.style.width = '0%';
                    loadFiles(); // 重新加载文件列表
                    loadMyFiles(); // 重新加载我的文件列表
                }, 1000);
            } else {
                uploadStats.innerText = '上传失败！';
                setTimeout(() => {
                    // 上传失败，重置状态
                    isUploading = false;
                    uploadContent.classList.remove('d-none');
                    uploadProgress.classList.add('d-none');
                    uploadProgressBar.style.width = '0%';
                }, 2000);
            }
        });
        
        xhr.addEventListener('error', () => {
            uploadStats.innerText = '网络错误！';
            setTimeout(() => {
                // 网络错误，重置状态
                isUploading = false;
                uploadContent.classList.remove('d-none');
                uploadProgress.classList.add('d-none');
                uploadProgressBar.style.width = '0%';
            }, 2000);
        });
        
        xhr.send(formData);
    }
}

// 加载文件列表
function loadFiles() {
    const fileListContainer = document.getElementById('file-list');
    if (!fileListContainer) {
        console.error('文件列表容器不存在');
        return;
    }
    
    // 显示加载状态
    fileListContainer.innerHTML = `
        <div class="col-12 text-center py-5" id="loading-files">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">加载中...</span>
            </div>
            <p class="mt-2">正在加载文件列表...</p>
        </div>
        <div class="col-12 text-center py-5 d-none" id="no-files">
            <i class="bi bi-file-earmark-x display-4 text-muted mb-3"></i>
            <p>暂无文件</p>
        </div>
    `;
    
    // 从服务器获取文件列表，添加时间戳防止缓存
    const timestamp = new Date().getTime();
    // 添加超时处理
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    fetch(`/api/files?timestamp=${timestamp}`, {
        headers: {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        },
        signal: controller.signal
    })
        .then(response => {
            clearTimeout(timeoutId);
            if (!response.ok) {
                throw new Error('网络响应错误，状态码：' + response.status);
            }
            return response.json();
        })
        .then(data => {
            clearTimeout(timeoutId);
            // 获取实际的文件数组
            const files = data.files || [];
            
            if (!files || files.length === 0) {
                // 显示无文件状态
                fileListContainer.innerHTML = `
                    <div class="col-12 text-center py-5" id="no-files">
                        <i class="bi bi-file-earmark-x display-4 text-muted mb-3"></i>
                        <p>暂无文件</p>
                    </div>
                `;
            } else {
                // 渲染文件列表
                let html = '';
                files.forEach(file => {
                    // 根据文件类型选择图标
                    let fileIcon = 'bi-file';
                    const fileType = file.name.split('.').pop().toLowerCase();
                    if (fileType === 'zip') fileIcon = 'bi-file-zip';
                    else if (fileType === 'pdf') fileIcon = 'bi-file-pdf';
                    else if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(fileType)) fileIcon = 'bi-file-image';
                    else if (['doc', 'docx'].includes(fileType)) fileIcon = 'bi-file-word';
                    else if (['xls', 'xlsx'].includes(fileType)) fileIcon = 'bi-file-excel';
                    else if (['mp4', 'avi', 'mov', 'wmv', 'flv'].includes(fileType)) fileIcon = 'bi-file-play';
                    else if (['mp3', 'wav', 'flac', 'aac', 'ogg'].includes(fileType)) fileIcon = 'bi-file-music';
                    else if (fileType === 'md') fileIcon = 'bi-filetype-md';
                    
                    // 格式化文件大小
                    let sizeText = '';
                    if (file.size < 1024) sizeText = `${file.size} B`;
                    else if (file.size < 1024 * 1024) sizeText = `${(file.size / 1024).toFixed(1)} KB`;
                    else sizeText = `${(file.size / (1024 * 1024)).toFixed(1)} MB`;
                    
                    // 格式化修改日期（使用API返回的modified字段）
                    const modifiedDate = new Date(file.modified * 1000).toLocaleString('zh-CN');
                    
                    // 构建文件卡片HTML
                    const encodedFileName = encodeURIComponent(file.name);
                    
                    html += `
                        <div class="col-md-4 col-lg-3">
                            <div class="file-card">
                                <div class="card-body">
                                    <div class="text-center mb-3">
                                        <i class="bi ${fileIcon} file-icon"></i>
                                    </div>
                                    <h5 class="card-title truncate" title="${file.name}">${file.name}</h5>
                                    <div class="d-flex justify-content-between align-items-center text-muted small mb-3">
                                        <span>${sizeText}</span>
                                        <span>${modifiedDate}</span>
                                    </div>
                                    <div class="file-actions">
                                        <a href="/file_detail?file=${encodedFileName}" class="btn btn-sm btn-info w-100 mb-2">
                                            <i class="bi bi-file-earmark-text me-1"></i> 详情
                                        </a>
                                        <a href="/download/${encodedFileName}" class="btn btn-sm btn-primary w-100 mb-2">
                                            <i class="bi bi-download me-1"></i> 下载
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                // 更新文件列表
                fileListContainer.innerHTML = html;
            }
        })
        .catch(error => {
            clearTimeout(timeoutId);
            console.error('获取文件列表失败:', error);
            // 显示错误信息
            fileListContainer.innerHTML = `
                <div class="col-12 text-center py-5">
                    <i class="bi bi-exclamation-triangle display-4 text-danger mb-3"></i>
                    <p>加载文件列表失败: ${error.message}</p>
                    <button class="btn btn-primary mt-2" onclick="loadFiles()">重试</button>
                </div>
            `;
        });
}



// 文件搜索功能
function initFileSearch() {
    const searchBtn = document.getElementById('search-btn');
    const searchInput = document.getElementById('search-input');
    
    if (!searchBtn || !searchInput) return;
    
    searchBtn.addEventListener('click', function() {
        const searchTerm = searchInput.value.toLowerCase();
        filterFiles(searchTerm);
    });
    
    searchInput.addEventListener('keyup', function(e) {
        if (e.key === 'Enter') {
            const searchTerm = this.value.toLowerCase();
            filterFiles(searchTerm);
        }
    });
}

// 文件过滤功能
function filterFiles(searchTerm) {
    const fileCards = document.querySelectorAll('.file-card');
    let foundFiles = false;
    
    fileCards.forEach(card => {
        const fileName = card.querySelector('.card-title').textContent.toLowerCase();
        if (fileName.includes(searchTerm)) {
            card.parentElement.classList.remove('d-none');
            foundFiles = true;
        } else {
            card.parentElement.classList.add('d-none');
        }
    });
    
    // 显示或隐藏"无文件"提示
    const noFilesElement = document.getElementById('no-files');
    if (!foundFiles && fileCards.length > 0) {
        noFilesElement.classList.remove('d-none');
    } else {
        noFilesElement.classList.add('d-none');
    }
}

// 图片画廊功能
function initImageGallery(images) {
    if (!images || images.length === 0) return;
    
    const galleryContainer = document.createElement('div');
    galleryContainer.className = 'gallery-container';
    
    // 主图片区域
    const mainImageContainer = document.createElement('div');
    mainImageContainer.className = 'main-image-container position-relative';
    
    const mainImage = document.createElement('img');
    mainImage.className = 'main-image';
    mainImage.src = images[0];
    mainImage.alt = '主图片';
    
    // 导航按钮
    const prevBtn = document.createElement('button');
    prevBtn.className = 'gallery-nav-btn prev';
    prevBtn.innerHTML = '<i class="bi bi-chevron-left"></i>';
    
    const nextBtn = document.createElement('button');
    nextBtn.className = 'gallery-nav-btn next';
    nextBtn.innerHTML = '<i class="bi bi-chevron-right"></i>';
    
    // 缩略图区域
    const thumbnailContainer = document.createElement('div');
    thumbnailContainer.className = 'thumbnail-container';
    
    // 图片信息
    const imageInfo = document.createElement('div');
    imageInfo.className = 'image-info';
    imageInfo.innerHTML = `<p>1/${images.length}</p>`;
    
    // 添加缩略图
    images.forEach((image, index) => {
        const thumbnail = document.createElement('img');
        thumbnail.className = `thumbnail ${index === 0 ? 'active' : ''}`;
        thumbnail.src = image;
        thumbnail.alt = `缩略图 ${index + 1}`;
        thumbnail.addEventListener('click', () => {
            mainImage.src = image;
            updateActiveThumbnail(index);
            updateImageInfo(index);
        });
        thumbnailContainer.appendChild(thumbnail);
    });
    
    // 添加事件监听
    prevBtn.addEventListener('click', () => {
        const currentIndex = images.indexOf(mainImage.src);
        const prevIndex = (currentIndex - 1 + images.length) % images.length;
        mainImage.src = images[prevIndex];
        updateActiveThumbnail(prevIndex);
        updateImageInfo(prevIndex);
    });
    
    nextBtn.addEventListener('click', () => {
        const currentIndex = images.indexOf(mainImage.src);
        const nextIndex = (currentIndex + 1) % images.length;
        mainImage.src = images[nextIndex];
        updateActiveThumbnail(nextIndex);
        updateImageInfo(nextIndex);
    });
    
    // 键盘事件
    document.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowLeft') {
            prevBtn.click();
        } else if (e.key === 'ArrowRight') {
            nextBtn.click();
        }
    });
    
    // 更新当前活动缩略图
    function updateActiveThumbnail(index) {
        document.querySelectorAll('.thumbnail').forEach((thumb, i) => {
            thumb.classList.toggle('active', i === index);
        });
    }
    
    // 更新图片信息
    function updateImageInfo(index) {
        imageInfo.innerHTML = `<p>${index + 1}/${images.length}</p>`;
    }
    
    // 组装画廊
    mainImageContainer.appendChild(mainImage);
    mainImageContainer.appendChild(prevBtn);
    mainImageContainer.appendChild(nextBtn);
    
    galleryContainer.appendChild(mainImageContainer);
    galleryContainer.appendChild(imageInfo);
    galleryContainer.appendChild(thumbnailContainer);
    
    return galleryContainer;
}

// 格式化文件大小
function formatBytes(bytes) {
    if (bytes === 0) return "0B";
    
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// 获取文件类型描述
function getFileTypeDescription(ext) {
    const types = {
        // 图片类型
        'ico': '图标文件',
        'jpg': 'JPEG 图片',
        'jpeg': 'JPEG 图片',
        'png': 'PNG 图片',
        'gif': 'GIF 图片',
        'bmp': '位图图片',
        'webp': 'WebP 图片',
        // 视频类型
        'mp4': 'MP4 视频',
        'webm': 'WebM 视频',
        'mov': 'QuickTime 视频',
        'avi': 'AVI 视频',
        'mkv': 'MKV 视频',
        'flv': 'FLV 视频',
        'wmv': 'WMV 视频',
        // 音频类型
        'mp3': 'MP3 音频',
        'wav': 'WAV 音频',
        'ogg': 'OGG 音频',
        'flac': 'FLAC 音频',
        'aac': 'AAC 音频',
        // 压缩包类型
        'zip': 'ZIP 压缩文件',
        'rar': 'RAR 压缩文件',
        '7z': '7-Zip 压缩文件',
        // 文档类型
        'doc': 'Word 文档',
        'docx': 'Word 文档',
        'xls': 'Excel 表格',
        'xlsx': 'Excel 表格',
        'pdf': 'PDF 文档',
        // 其他
        'adofai': 'Adofai 谱面文件'
    };

    return types[ext] || '未知文件类型';
}

// 用户页面初始化
function initUserPage(userData) {
    // 初始化文件上传
    initFileUpload();
    
    // 初始化文件列表
    loadFiles();
    
    // 初始化文件搜索
    initFileSearch();
    
    // 刷新按钮
    const refreshBtn = document.getElementById('refreshFiles');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function(e) {
            e.preventDefault();
            console.log('开始同步刷新文件列表...');
            
            // 先显示加载状态
            const fileListContainer = document.getElementById('file-list');
            const myFilesList = document.getElementById('my-files-list');
            
            if (fileListContainer) {
                fileListContainer.innerHTML = `
                    <div class="col-12 text-center py-5" id="loading-files">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">加载中...</span>
                        </div>
                        <p class="mt-2">正在加载文件列表...</p>
                    </div>
                `;
            }
            
            if (myFilesList) {
                myFilesList.innerHTML = `
                    <div class="col-12 text-center py-5" id="loading-my-files">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">加载中...</span>
                        </div>
                        <p class="mt-2">正在加载我的文件列表...</p>
                    </div>
                `;
            }
            
            // 并行加载两个列表，确保同步
            Promise.all([
                new Promise((resolve) => {
                    loadFiles();
                    setTimeout(resolve, 100); // 给一点时间让loadFiles开始执行
                }),
                new Promise((resolve) => {
                    loadMyFiles();
                    setTimeout(resolve, 100); // 给一点时间让loadMyFiles开始执行
                })
            ]).then(() => {
                console.log('文件列表同步刷新完成');
            });
        });
    }
    
    // 退出登录
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function() {
            // 清除客户端存储的token
            localStorage.removeItem('auth_token');
            sessionStorage.removeItem('auth_token');
            localStorage.removeItem('token_created_time');
            sessionStorage.removeItem('token_created_time');
            localStorage.removeItem('username');
            sessionStorage.removeItem('username');
            
            // 检查当前URL中是否包含admin相关参数
            const urlParams = new URLSearchParams(window.location.search);
            const fromAdmin = urlParams.get('from') === 'admin' || urlParams.get('return_to') === 'admin';
            
            // 或者检查用户是否为管理员（如果有相关信息存储在localStorage或sessionStorage中）
            const isAdmin = sessionStorage.getItem('is_admin') === 'true' || localStorage.getItem('is_admin') === 'true';
            
            if (fromAdmin || isAdmin) {
                // 如果是从管理页过来的，或者是管理员，调用管理员退出路由
                window.location.href = '/admin/logout';
            } else {
                // 否则，调用普通用户退出路由
                window.location.href = '/logout';
            }
        });
    }
    
    // 初始化侧边栏切换
    initSidebarSwitch();
    
    // 初始化我的文件页面
    initMyFilesPage();
    
    // 初始化我的账户页面
    initMyAccountPage(userData);
}

// 初始化侧边栏切换
function initSidebarSwitch() {
    const sidebarLinks = document.querySelectorAll('.sidebar .nav-link');
    const contentSections = document.querySelectorAll('.content-section');
    
    sidebarLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // 移除所有活动链接和内容区域的active类
            sidebarLinks.forEach(l => l.classList.remove('active'));
            contentSections.forEach(section => section.classList.add('d-none'));
            
            // 添加当前链接的active类
            this.classList.add('active');
            
            // 显示对应的内容区域
            const targetId = this.getAttribute('href').substring(1);
            const targetSection = document.getElementById(targetId);
            if (targetSection) {
                targetSection.classList.remove('d-none');
            }
        });
    });
}

// 初始化我的文件页面
function initMyFilesPage() {
    // 我的文件搜索功能
    const myFilesSearchBtn = document.getElementById('my-files-search-btn');
    const myFilesSearchInput = document.getElementById('my-files-search-input');
    
    if (myFilesSearchBtn && myFilesSearchInput) {
        myFilesSearchBtn.addEventListener('click', function() {
            const searchTerm = myFilesSearchInput.value.toLowerCase();
            filterMyFiles(searchTerm);
        });
        
        myFilesSearchInput.addEventListener('keyup', function(e) {
            if (e.key === 'Enter') {
                const searchTerm = this.value.toLowerCase();
                filterMyFiles(searchTerm);
            }
        });
    }
    
    // 加载我的文件列表
    loadMyFiles();
}

// 加载我的文件列表
function loadMyFiles() {
    const myFilesLoading = document.getElementById('my-files-loading');
    const myFilesEmpty = document.getElementById('my-files-empty');
    const myFilesList = document.getElementById('my-files-list');
    
    if (myFilesLoading && myFilesEmpty && myFilesList) {
        myFilesLoading.classList.remove('d-none');
        myFilesEmpty.classList.add('d-none');
        myFilesList.innerHTML = '';
        
        // 调用API获取我的文件列表，添加时间戳防止缓存
        const timestamp = new Date().getTime();
        // 添加超时处理
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        
        fetch(`/api/my_files?timestamp=${timestamp}`, {
            headers: {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            },
            signal: controller.signal
        })
            .then(response => {
                clearTimeout(timeoutId);
                if (!response.ok) {
                    throw new Error('网络响应错误，状态码：' + response.status);
                }
                return response.json();
            })
            .then(data => {
                clearTimeout(timeoutId);
                myFilesLoading.classList.add('d-none');
                
                if (data.files && data.files.length > 0) {
                    myFilesEmpty.classList.add('d-none');
                    
                    // 渲染文件列表
                    let html = '';
                    data.files.forEach(file => {
                        html += `
                            <div class="file-item p-3 border rounded shadow-sm mb-3">
                                <div class="d-flex align-items-center justify-content-between">
                                    <div class="d-flex align-items-center">
                                        <i class="bi bi-file-earmark fs-3 me-3 text-primary"></i>
                                        <div>
                                            <div class="file-name">${file.name}</div>
                                            <div class="file-meta text-sm">
                                                ${formatBytes(file.size)} • ${new Date(file.modified * 1000).toLocaleString()} • 下载 ${file.download_count} 次
                                            </div>
                                        </div>
                                    </div>
                                    <div class="d-flex gap-2">
                                        <a href="/download/${encodeURIComponent(file.filename)}" class="btn btn-sm btn-primary">
                                            <i class="bi bi-download"></i> 下载
                                        </a>
                                        <button class="btn btn-sm btn-danger delete-file-btn" data-filename="${file.filename}">
                                            <i class="bi bi-trash"></i> 删除
                                        </button>
                                    </div>
                                </div>
                            </div>
                        `;
                    });
                    
                    // 一次性更新DOM，提高性能
                    myFilesList.innerHTML = html;
                    
                    // 添加删除按钮事件监听
                    document.querySelectorAll('.delete-file-btn').forEach(btn => {
                        btn.addEventListener('click', function() {
                            const filename = this.getAttribute('data-filename');
                            showDeleteModal(filename);
                        });
                    });
                } else {
                    myFilesEmpty.classList.remove('d-none');
                }
            })
            .catch(error => {
                clearTimeout(timeoutId);
                myFilesLoading.classList.add('d-none');
                myFilesEmpty.innerHTML = `
                    <i class="bi bi-exclamation-triangle display-4 text-danger mb-3"></i>
                    <p>加载文件失败: ${error.message}</p>
                    <button class="btn btn-primary mt-2" onclick="loadMyFiles()">重试</button>
                `;
                myFilesEmpty.classList.remove('d-none');
                console.error('加载我的文件失败:', error);
            });
    }
}

// 初始化删除确认模态框
function initDeleteModal() {
    // 检查模态框是否已存在
    if (!document.getElementById('delete-modal')) {
        const modalHTML = `
            <div class="modal fade" id="delete-modal" tabindex="-1" aria-labelledby="delete-modal-label" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="delete-modal-label">删除确认</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <p id="delete-modal-message">确定要删除此文件吗？</p>
                            <div class="mt-3 alert alert-danger d-none" id="delete-error" role="alert">
                                <strong>删除失败:</strong> <span id="delete-error-message"></span>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                            <button type="button" class="btn btn-danger" id="confirm-delete-btn">确认删除</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHTML);
    }
}

// 初始化状态提示模态框
function initStatusModal() {
    // 检查模态框是否已存在
    if (!document.getElementById('status-modal')) {
        const modalHTML = `
            <div class="modal fade" id="status-modal" tabindex="-1" aria-labelledby="status-modal-label" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="status-modal-label">操作结果</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <div class="d-flex align-items-center">
                                <div id="status-icon" class="me-3 fs-3"></div>
                                <div id="status-message"></div>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-primary" data-bs-dismiss="modal">确定</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHTML);
    }
}

// 显示状态提示模态框
function showStatusModal(message, isSuccess = true, callback = null) {
    initStatusModal();
    
    const modal = new bootstrap.Modal(document.getElementById('status-modal'));
    const iconElement = document.getElementById('status-icon');
    const messageElement = document.getElementById('status-message');
    const confirmBtn = document.querySelector('#status-modal .btn-primary');
    
    // 设置图标和消息
    if (isSuccess) {
        iconElement.className = 'bi bi-check-circle text-success me-3 fs-3';
        messageElement.textContent = message;
    } else {
        iconElement.className = 'bi bi-exclamation-circle text-danger me-3 fs-3';
        messageElement.textContent = message;
    }
    
    // 如果提供了回调函数，在点击确定按钮后执行
    if (callback && typeof callback === 'function') {
        // 先移除可能存在的事件监听器，避免多次绑定
        confirmBtn.onclick = null;
        // 添加新的事件监听器
        confirmBtn.addEventListener('click', function() {
            callback();
        });
    }
    
    modal.show();
}

// 显示删除确认模态框
function showDeleteModal(filename) {
    initDeleteModal();
    
    const modal = new bootstrap.Modal(document.getElementById('delete-modal'));
    const messageElement = document.getElementById('delete-modal-message');
    const errorElement = document.getElementById('delete-error');
    const confirmBtn = document.getElementById('confirm-delete-btn');
    
    messageElement.textContent = `确定要删除文件 "${filename}" 吗？`;
    errorElement.classList.add('d-none');
    
    // 添加确认删除事件监听
    confirmBtn.onclick = function() {
        // 禁用确认按钮，防止重复点击
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> 删除中...';
        
        deleteMyFile(filename, modal, confirmBtn);
    };
    
    modal.show();
}

// 删除我的文件
function deleteMyFile(filename, modal, confirmBtn) {
    fetch('/api/delete_my_file', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ filename: filename })
    })
    .then(response => {
        // 恢复按钮状态
        confirmBtn.disabled = false;
        confirmBtn.innerHTML = '确认删除';
        
        // 检查Token是否过期
        if (response.status === 401 || response.status === 302) {
            // Token过期，重定向到登录页
            window.location.href = '/';
            return Promise.reject(new Error('Token过期'));
        }
        return response.json();
    })
    .then(data => {
        // 无论成功还是失败，都关闭当前模态框
        modal.hide();
        
        if (data.status === 'success') {
            // 显示成功提示，并在用户点击确定后刷新文件列表
            showStatusModal('文件删除成功！', true, function() {
                // 重新加载我的文件列表
                loadMyFiles();
                // 同时更新主文件列表
                loadFiles();
                // 更新存储空间显示
                updateStorageDisplay();
            });
        } else {
            // 显示错误提示，并在用户点击确定后刷新文件列表
            showStatusModal(`删除失败: ${data.message}`, false, function() {
                // 失败时也刷新文件列表，确保显示的文件都是可操作的
                loadMyFiles();
                loadFiles();
            });
        }
    })
    .catch(error => {
        // 恢复按钮状态
        confirmBtn.disabled = false;
        confirmBtn.innerHTML = '确认删除';
        
        // 关闭当前模态框
        modal.hide();
        
        if (error.message !== 'Token过期') {
            // 显示错误提示，并在用户点击确定后刷新文件列表
            showStatusModal(`删除失败: ${error.message}`, false, function() {
                // 异常时也刷新文件列表
                loadMyFiles();
                loadFiles();
            });
            console.error('删除文件失败:', error);
        }
    });
}

// 过滤我的文件
function filterMyFiles(searchTerm) {
    // 这里可以添加过滤我的文件的逻辑
    console.log('过滤我的文件:', searchTerm);
}

// 初始化我的账户页面
function initMyAccountPage(userData) {
    // 如果有用户数据，更新账户信息
    if (userData) {
        // 这里可以根据需要更新账户信息
        console.log('用户数据:', userData);
    }
    
    // 初始化token信息显示
    initTokenInfo();
}

// 初始化token信息显示
function initTokenInfo() {
    const tokenExpiryElement = document.getElementById('token-expiry');
    const currentTokenElement = document.getElementById('current-token');
    
    if (!tokenExpiryElement || !currentTokenElement) return;
    
    // 获取token
    const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
    
    if (token) {
        // 显示当前token
        currentTokenElement.textContent = token;
        
        // 添加点击复制token功能
        currentTokenElement.addEventListener('click', function() {
            navigator.clipboard.writeText(token)
                .then(() => {
                    showTokenCopyToast('已将token复制到剪贴板', currentTokenElement);
                })
                .catch(err => {
                    console.error('复制失败:', err);
                    showTokenCopyToast('复制Token失败！', currentTokenElement, false);
                });
        });
        
        // 获取token有效期（需要后端支持，这里暂时使用模拟数据）
        // 实际应用中，应该从服务器获取token的创建时间和有效期
        fetchTokenExpiry(token);
    } else {
        tokenExpiryElement.textContent = '未登录';
        currentTokenElement.textContent = '无';
    }
}

// 显示token复制提示
function showTokenCopyToast(message, targetElement, isSuccess = true) {
    // 检查是否已经存在toast元素
    let toastContainer = document.getElementById('token-toast-container');
    if (!toastContainer) {
        // 创建toast容器
        toastContainer = document.createElement('div');
        toastContainer.id = 'token-toast-container';
        toastContainer.className = 'toast-container position-fixed p-3';
        toastContainer.style.zIndex = '1055';
        document.body.appendChild(toastContainer);
    }
    
    // 创建toast元素
    const toastId = 'token-toast-' + Date.now();
    const toastHTML = `
        <div id="${toastId}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-body p-3 m-0" style="background-color: rgba(13, 110, 253, 0.8); color: white; border-radius: 8px; backdrop-filter: blur(10px); box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);">
                ${message}
            </div>
        </div>
    `;
    
    // 添加toast到容器
    toastContainer.innerHTML = toastHTML;
    
    // 获取toast元素
    const toastElement = document.getElementById(toastId);
    
    // 如果提供了目标元素，计算位置
    if (targetElement) {
        const targetRect = targetElement.getBoundingClientRect();
        // 计算toast宽度，确保不超出页面
        const toastWidth = toastElement.offsetWidth;
        const windowWidth = window.innerWidth;
        let left = targetRect.left + (targetRect.width - toastWidth) / 2;
        
        // 确保toast不超出页面
        if (left < 20) left = 20;
        if (left + toastWidth > windowWidth - 20) left = windowWidth - toastWidth - 20;
        
        toastContainer.style.top = `${targetRect.top - 50}px`;
        toastContainer.style.left = `${left}px`;
    } else {
        // 默认居中显示
        toastContainer.style.top = '50%';
        toastContainer.style.left = '50%';
        toastContainer.style.transform = 'translate(-50%, -50%)';
    }
    
    // 初始化并显示toast
    const toast = new bootstrap.Toast(toastElement, {
        animation: true,
        autohide: true,
        delay: 2000
    });
    
    toast.show();
    
    // 显示后清理toast元素
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

// 获取token有效期
function fetchTokenExpiry(token) {
    const tokenExpiryElement = document.getElementById('token-expiry');
    const tokenInfoElement = document.querySelector('.token-info');
    if (!tokenExpiryElement || !tokenInfoElement) return;
    
    let expiryTime = null; // 存储token过期时间戳
    let lastFetchTime = 0; // 上次从后端获取时间的时间戳
    const FETCH_INTERVAL = 60; // 每分钟从后端获取一次（秒）
    
    // 从后端获取token过期时间
    function fetchExpiryFromBackend() {
        fetch('/api/token_expiry', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (response.status === 401) {
                // Token无效或已过期
                tokenExpiryElement.textContent = 'Token已过期';
                tokenInfoElement.classList.add('expired');
                // 延迟3秒后重定向到登录页
                setTimeout(() => {
                    window.location.href = '/';
                }, 3000);
                return;
            }
            return response.json();
        })
        .then(data => {
            if (data.status === 'success') {
                // 更新过期时间戳和上次获取时间
                expiryTime = data.expiry;
                lastFetchTime = Math.floor(Date.now() / 1000);
            } else {
                console.error('获取token有效期失败:', data.message);
            }
        })
        .catch(error => {
            console.error('获取token有效期失败:', error);
        });
    }
    
    // 更新token有效期显示
    function updateTokenDisplay() {
        // 检查是否需要从后端获取新的过期时间
        const currentTime = Math.floor(Date.now() / 1000);
        if (!expiryTime || (currentTime - lastFetchTime) >= FETCH_INTERVAL) {
            fetchExpiryFromBackend();
        }
        
        if (expiryTime) {
            // 计算剩余时间
            const remainingSeconds = Math.max(0, expiryTime - currentTime);
            
            if (remainingSeconds <= 0) {
                tokenExpiryElement.textContent = 'Token已过期';
                tokenInfoElement.classList.add('expired');
                setTimeout(() => {
                    window.location.href = '/';
                }, 3000);
                return;
            }
            
            // 格式化剩余时间
            const hours = Math.floor(remainingSeconds / 3600);
            const minutes = Math.floor((remainingSeconds % 3600) / 60);
            const seconds = remainingSeconds % 60;
            
            let expiryText = '';
            if (hours > 0) {
                expiryText += `${hours}小时`;
            }
            if (minutes > 0 || hours > 0) {
                expiryText += `${minutes}分钟`;
                if (hours > 0) expiryText += ' ';
            }
            expiryText += `${seconds}秒`;
            
            tokenExpiryElement.textContent = expiryText;
        }
    }
    
    // 初始从后端获取过期时间
    fetchExpiryFromBackend();
    
    // 每秒更新一次显示
    setInterval(updateTokenDisplay, 1000);
}

// 文件详情页初始化
function initFileDetailPage() {
    // 从URL获取文件名
    const params = new URLSearchParams(window.location.search);
    const filename = params.get('file');
    
    if (!filename) {
        alert('未指定文件');
        window.location.href = '/';
        return;
    }
    
    // 设置文件名
    const fileNameElement = document.getElementById('file-name');
    if (fileNameElement) {
        fileNameElement.textContent = filename;
    }
    
    // 获取文件信息
    fetch(`/api/file_info?filename=${encodeURIComponent(filename)}`)
        .then(response => response.json())
        .then(fileInfo => {
            if (!fileInfo) {
                throw new Error('文件信息获取失败');
            }
            
            // 更新文件信息
            const fileSizeElement = document.getElementById('file-size');
            const downloadCountElement = document.getElementById('download-count');
            const uploadTimeElement = document.getElementById('upload-time');
            const modifiedTimeElement = document.getElementById('modified-time');
            const fileTypeElement = document.getElementById('file-type');
            const fileTypeFullElement = document.getElementById('file-type-full');
            const downloadBtnElement = document.getElementById('download-btn');
            
            if (fileSizeElement) {
                fileSizeElement.textContent = formatBytes(fileInfo.size);
            }
            
            if (downloadCountElement) {
                downloadCountElement.textContent = fileInfo.download_count || 0;
            }
            
            if (uploadTimeElement && fileInfo.created) {
                uploadTimeElement.textContent = new Date(fileInfo.created * 1000).toLocaleString();
            }
            
            if (modifiedTimeElement && fileInfo.modified) {
                modifiedTimeElement.textContent = new Date(fileInfo.modified * 1000).toLocaleString();
            }
            
            if (downloadBtnElement) {
                downloadBtnElement.href = `/download/${encodeURIComponent(filename)}`;
            }
            
            // 根据文件类型渲染预览
            const ext = filename.split('.').pop().toLowerCase();
            if (fileTypeElement) {
                fileTypeElement.textContent = ext.toUpperCase();
            }
            
            if (fileTypeFullElement) {
                fileTypeFullElement.textContent = getFileTypeDescription(ext);
            }
            
            // 设置文件图标
            const fileIconElement = document.getElementById('file-icon');
            if (fileIconElement) {
                let iconClass = 'bi-file-text'; // 使用横向的文本文件图标作为默认
                if (ext === 'zip') iconClass = 'bi-filetype-zip'; // 横向zip图标
                else if (ext === 'pdf') iconClass = 'bi-filetype-pdf'; // 横向pdf图标
                else if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) iconClass = 'bi-filetype-jpg'; // 横向图片图标
                else if (['doc', 'docx'].includes(ext)) iconClass = 'bi-filetype-docx'; // 横向word图标
                else if (['xls', 'xlsx'].includes(ext)) iconClass = 'bi-filetype-xlsx'; // 横向excel图标
                else if (['mp4', 'avi', 'mov', 'wmv', 'flv'].includes(ext)) iconClass = 'bi-filetype-mp4'; // 横向视频图标
                else if (['mp3', 'wav', 'flac', 'aac', 'ogg'].includes(ext)) iconClass = 'bi-filetype-mp3'; // 横向音频图标
                else if (ext === 'md') iconClass = 'bi-filetype-md'; // 横向md图标
                
                fileIconElement.className = iconClass;
            }
            
            // 渲染文件预览
            renderPreview(filename, fileInfo);
        })
        .catch(error => {
            console.error('获取文件信息失败:', error);
            const previewContainer = document.getElementById('preview-container');
            if (previewContainer) {
                previewContainer.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle"></i> 加载文件信息失败: ${error.message}
                    </div>
                `;
            }
        });
}

// 获取文件类型描述
function getFileTypeDescription(ext) {
    const types = {
        // 图片类型
        'ico': '图标文件',
        'jpg': 'JPEG 图片',
        'jpeg': 'JPEG 图片',
        'png': 'PNG 图片',
        'gif': 'GIF 图片',
        'bmp': '位图图片',
        'webp': 'WebP 图片',
        // 视频类型
        'mp4': 'MP4 视频',
        'webm': 'WebM 视频',
        'ogg': 'OGG 视频',
        'mov': 'QuickTime 视频',
        'avi': 'AVI 视频',
        'mkv': 'MKV 视频',
        'flv': 'FLV 视频',
        'wmv': 'WMV 视频',
        '3gp': '3GP 视频',
        'm4v': 'M4V 视频',
        // 文档类型
        'pdf': 'PDF 文档',
        'txt': '文本文件',
        'doc': 'Word 文档',
        'docx': 'Word 文档',
        'xls': 'Excel 表格',
        'xlsx': 'Excel 表格',
        'ppt': 'PowerPoint 演示',
        'pptx': 'PowerPoint 演示',
        // 压缩包类型
        'zip': 'ZIP 压缩文件',
        'rar': 'RAR 压缩文件',
        '7z': '7-Zip 压缩文件',
        'gz': 'GZip 压缩文件',
        'bz2': 'BZip2 压缩文件',
        // 音频类型
        'mp3': 'MP3 音频文件',
        'wav': 'WAV 音频文件',
        'ogg': 'OGG 音频文件',
        'flac': 'FLAC 音频文件',
        'aac': 'AAC 音频文件',
        // Windows特有文件类型
        'exe': 'Windows可执行文件',
        'bat': 'Windows批处理文件',
        'msi': 'Windows安装程序',
        'dll': 'Windows动态链接库',
        'cmd': 'Windows命令文件',
        'reg': 'Windows注册表文件',
        'sys': 'Windows系统文件',
        'cab': 'Windows安装包',
        'inf': 'Windows安装信息文件',
        'scr': 'Windows屏幕保护程序',
        'com': 'Windows命令文件',
        'cpl': 'Windows控制面板项',
        'msc': 'Windows控制台应用程序',
        'ocx': 'Windows控件',
        'ax': 'WindowsActiveX控件',
        'chm': 'Windows帮助文件',
        'msp': 'Windows修补程序',
        'msu': 'Windows更新程序',
        'mui': 'Windows多语言界面文件',
        'ps1': 'Windows PowerShell脚本',
        'psm1': 'Windows PowerShell模块',
        'psd1': 'Windows PowerShell数据文件',
        'ps1xml': 'Windows PowerShell配置文件',
        'pssc': 'Windows PowerShell配置文件',
        'psexec': 'Windows远程执行工具',
        // 编程语言文件类型
        'sh': 'Shell脚本',
        'py': 'Python脚本',
        'java': 'Java源代码',
        'cpp': 'C++源代码',
        'c': 'C源代码',
        'go': 'Go源代码',
        'rb': 'Ruby脚本',
        'swift': 'Swift源代码',
        'rs': 'Rust源代码',
        'kt': 'Kotlin源代码',
        'h': 'C/C++头文件',
        // web文件类型
        'js': 'JavaScript脚本',
        'ts': 'TypeScript脚本',
        'php': 'PHP脚本',
        'html': 'HTML文件',
        'css': 'CSS文件',
        // 配置文件类型
        'json': 'JSON文件',
        'xml': 'XML文件',
        'yaml': 'YAML文件',
        'yml': 'YAML文件',
        'toml': 'TOML文件',
        'ini': 'INI文件',
        'conf': '配置文件',
        // 数据库文件类型
        'sql': 'SQL文件',
        'db': '数据库文件',
        'mdb': 'Microsoft Access数据库文件',
        'sqlite': 'SQLite数据库文件',
        'dbf': 'dBASE数据库文件',
        'accdb': 'Microsoft Access数据库文件',
        'mdbx': 'Microsoft Access数据库文件',
        'sqlitedb': 'SQLite数据库文件',
        'sqlite3': 'SQLite数据库文件',
        'sqlite2': 'SQLite数据库文件',
        'db3': 'SQLite数据库文件',
        'db2': 'SQLite数据库文件',
        'db4': 'SQLite数据库文件',
        'db5': 'SQLite数据库文件',
        'db6': 'SQLite数据库文件',
        'db7': 'SQLite数据库文件',
        'db8': 'SQLite数据库文件',
        'db9': 'SQLite数据库文件',
        // Mac OS特有文件类型
        'app': 'Mac OS应用程序',
        'dmg': 'Mac OS磁盘映像',
        'pkg': 'Mac OS安装包',
        'command': 'Mac OS命令文件',
        'plist': 'Mac OS属性列表文件',
        'icns': 'Mac OS图标文件',
        // 日志文件类型
        'log': '日志文件',
        // 其它常见文件类型
        'chm': '帮助文件',
        'md': 'Markdown文件',
        'csv': '逗号分隔值文件',
        'tsv': '制表符分隔值文件',
        'rtf': '富文本格式文件',
        'odt': 'OpenDocument文本文件',
        'epub': '电子书文件',
        'po': 'PO文件',
        'mo': 'MO文件',
        'pot': 'POT文件',
        'lang': '语言文件',
        'properties': 'Java属性文件',
        //特殊文件
        'aktp': 'Advanced_Key_Tools_GUI加密文件'
    };

    return types[ext] || '未知文件类型';
}



// 渲染文件预览
function renderPreview(filename, fileInfo) {
    const previewContainer = document.getElementById('preview-container');
    if (!previewContainer) return;
    
    const ext = filename.split('.').pop().toLowerCase();
    const decodedFilename = decodeURIComponent(filename);
    
    // 根据文件类型渲染预览
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico'].includes(ext)) {
        // 图片预览
        previewContainer.innerHTML = `
            <img src="/preview/${encodeURIComponent(filename)}" 
                 class="image-preview" alt="${decodedFilename}" style="max-width: 100%; max-height: 600px; object-fit: contain;">
        `;
    } else if (['mp4', 'webm', 'ogg', 'mov', 'avi'].includes(ext)) {
        // 视频预览
        let mimeType = 'video/' + ext;
        if (ext === 'mp4') mimeType = 'video/mp4';
        else if (ext === 'webm') mimeType = 'video/webm';
        else if (ext === 'ogg') mimeType = 'video/ogg';
        else if (ext === 'mov') mimeType = 'video/quicktime';
        else if (ext === 'avi') mimeType = 'video/x-msvideo';
        
        previewContainer.innerHTML = `
            <video id="video-player" controls class="video-player" preload="metadata" style="max-width: 100%; max-height: 600px;">
                <source src="/preview/${encodeURIComponent(filename)}" type="${mimeType}">
                <p>您的浏览器不支持视频播放。请尝试以下操作：</p>
                <ul>
                    <li>更新您的浏览器到最新版本</li>
                    <li>尝试使用不同的浏览器</li>
                    <li><a href="/preview/${encodeURIComponent(filename)}" onclick="downloadFile('${encodeURIComponent(filename)}'); return false;">下载文件</a>后使用本地播放器观看</li>
                </ul>
            </video>
        `;
    } else if (['mp3', 'wav', 'ogg', 'flac', 'aac'].includes(ext)) {
        // 音频预览
        const audioPath = `/preview/${encodeURIComponent(filename)}`;
        previewContainer.innerHTML = `
            <div class="text-center">
                <audio controls class="audio-player" style="width: 100%; max-width: 500px;">
                    <source src="${audioPath}" type="audio/mpeg">
                    <source src="${audioPath}" type="audio/ogg">
                    <source src="${audioPath}" type="audio/wav">
                    您的浏览器不支持音频播放。
                </audio>
            </div>
        `;
    } else if (['html', 'htm', 'md', 'markdown'].includes(ext)) {
        // 处理HTML和MD文件的渲染预览
        if (ext === 'md' || ext === 'markdown') {
            // MD文件使用iframe嵌入Markdown查看器
            // 检测当前主题
            const isDark = document.documentElement.hasAttribute('data-theme');
            const theme = isDark ? 'dark' : 'light';
            
            // 创建预览选项卡
            previewContainer.innerHTML = `
                <div class="preview-tabs mb-3">
                    <ul class="nav nav-tabs" id="preview-tabs" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" id="preview-tab" data-bs-toggle="tab" data-bs-target="#preview-content" type="button" role="tab" aria-controls="preview-content" aria-selected="true">
                                <i class="bi bi-eye"></i> 预览
                            </button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="code-tab" data-bs-toggle="tab" data-bs-target="#code-content" type="button" role="tab" aria-controls="code-content" aria-selected="false">
                                <i class="bi bi-code"></i> 源代码
                            </button>
                        </li>
                    </ul>
                    <div class="tab-content" id="preview-tab-content">
                        <div class="tab-pane fade show active" id="preview-content" role="tabpanel" aria-labelledby="preview-tab">
                            <iframe src="/markdown-viewer?file=${encodeURIComponent(filename)}&theme=${theme}" style="width: 100%; height: 600px; border: none; border-radius: 6px;"></iframe>
                        </div>
                        <div class="tab-pane fade" id="code-content" role="tabpanel" aria-labelledby="code-tab">
                            <pre class="text-content"></pre>
                        </div>
                    </div>
                </div>
            `;
            
            // 获取源代码
            fetch(`/preview/${encodeURIComponent(filename)}`)
                .then(response => response.text())
                .then(content => {
                    const codeContent = document.querySelector('#code-content pre');
                    if (codeContent) {
                        codeContent.textContent = content;
                    }
                })
                .catch(error => {
                    console.error('获取源代码失败:', error);
                });
        } else {
            // HTML文件处理
            fetch(`/preview/${encodeURIComponent(filename)}`)
                .then(response => response.text())
                .then(content => {
                    // 创建预览选项卡
                    previewContainer.innerHTML = `
                        <div class="preview-tabs mb-3">
                            <ul class="nav nav-tabs" id="preview-tabs" role="tablist">
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link active" id="preview-tab" data-bs-toggle="tab" data-bs-target="#preview-content" type="button" role="tab" aria-controls="preview-content" aria-selected="true">
                                        <i class="bi bi-eye"></i> 预览
                                    </button>
                                </li>
                                <li class="nav-item" role="presentation">
                                    <button class="nav-link" id="code-tab" data-bs-toggle="tab" data-bs-target="#code-content" type="button" role="tab" aria-controls="code-content" aria-selected="false">
                                        <i class="bi bi-code"></i> 源代码
                                    </button>
                                </li>
                            </ul>
                            <div class="tab-content" id="preview-tab-content">
                                <div class="tab-pane fade show active" id="preview-content" role="tabpanel" aria-labelledby="preview-tab">
                                    <div class="preview-container html-preview" id="rendered-preview"></div>
                                </div>
                                <div class="tab-pane fade" id="code-content" role="tabpanel" aria-labelledby="code-tab">
                                    <pre class="text-content">${content}</pre>
                                </div>
                            </div>
                        </div>
                    `;
                    
                    // 渲染内容
                    const renderedPreview = document.getElementById('rendered-preview');
                    // 直接渲染HTML
                    renderedPreview.innerHTML = content;
                })
                .catch(error => {
                    previewContainer.innerHTML = `
                        <div class="alert alert-danger">
                            <i class="bi bi-exclamation-triangle"></i> 加载文件内容失败: ${error.message}
                            <p class="mt-2">请尝试<a href="/preview/${encodeURIComponent(filename)}" download>下载文件</a>后用浏览器打开</p>
                        </div>
                    `;
                });
        }
    } else if (['txt', 'json', 'xml', 'yaml', 'yml', 'ini', 'cfg', 'conf', 'csv', 'tsv', 'log', 'css', 'js', 'py', 'java', 'c', 'cpp', 'h', 'hpp', 'cs', 'php', 'rb', 'go', 'rs', 'jsx', 'tsx', 'vue', 'sql', 'gitignore', 'dockerignore', 'properties'].includes(ext)) {
        // 处理文本文件和代码文件
        fetch(`/preview/${encodeURIComponent(filename)}`)
            .then(response => response.text())
            .then(content => {
                previewContainer.innerHTML = `
                    <pre class="text-content" style="max-height: 600px; overflow: auto; background-color: var(--preview-bg); padding: 15px; border-radius: 8px;">${content}</pre>
                `;
            })
            .catch(error => {
                previewContainer.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle"></i> 加载文本内容失败: ${error.message}
                        <p class="mt-2">请尝试<a href="/preview/${encodeURIComponent(filename)}" download>下载文件</a>后用文本编辑器打开</p>
                    </div>
                `;
            });
    } else if (ext === 'zip') {
        // ZIP文件预览
        // 检查ZIP文件内部是否包含可预览的媒体文件和Adofai谱面信息
        Promise.all([
            fetch(`/api/check_zip_media?filename=${encodeURIComponent(filename)}`).then(r => r.json()),
            fetch(`/api/adofai_level_info?filename=${encodeURIComponent(filename)}&file_type=zip`).then(r => r.json()).catch(() => null)
        ])
        .then(([data, adofaiData]) => {
                // 构建完整的媒体预览HTML
                let html = `
                    <div class="media-container">
                        <h4>ZIP压缩文件预览</h4>
                `;
                
                // 如果有Adofai谱面信息（至少有歌曲名称、艺术家或作者之一），显示谱面信息
                const hasValidLevelInfo = adofaiData && adofaiData.status === 'success' && adofaiData.level_info && 
                                         (adofaiData.level_info.song || adofaiData.level_info.artist || adofaiData.level_info.author || 
                                          adofaiData.level_info.difficulty || adofaiData.level_info.bpm || adofaiData.level_info.steps_count > 0);
                
                if (hasValidLevelInfo) {
                    html += `
                        <div class="adofai-preview mt-4">
                            <h5>Adofai谱面文件信息</h5>
                            <div class="adofai-info">
                                <div class="meta-grid">
                                    <div class="meta-item">
                                        <span class="meta-label">歌曲名称</span>
                                        <span class="meta-value">${adofaiData.level_info.song || '未知'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">艺术家</span>
                                        <span class="meta-value">${adofaiData.level_info.artist || '未知'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">谱面作者</span>
                                        <span class="meta-value">${adofaiData.level_info.author || '未知'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">难度</span>
                                        <span class="meta-value">${adofaiData.level_info.difficulty || '未知'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">BPM</span>
                                        <span class="meta-value">${adofaiData.level_info.bpm || '未知'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">步数</span>
                                        <span class="meta-value">${adofaiData.level_info.steps_count || '0'}步</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">音频文件</span>
                                        <span class="meta-value">${adofaiData.audio_file || '无'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">图片文件数量</span>
                                        <span class="meta-value">${adofaiData.image_files ? adofaiData.image_files.length : 0}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">视频文件数量</span>
                                        <span class="meta-value">${adofaiData.video_files ? adofaiData.video_files.length : 0}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }
                
                // 显示图片画廊
                if (data.images && data.images.length > 0) {
                    html += `
                        <div class="mt-4">
                            <h5>图片预览</h5>
                            <div id="zip-image-gallery"></div>
                        </div>
                    `;
                }
                
                // 显示视频播放器
                if (data.videos && data.videos.length > 0) {
                    html += `
                        <div class="mt-4">
                            <h5>视频预览</h5>
                            <div class="video-preview-list">
                    `;
                    
                    data.videos.forEach((video, index) => {
                        html += `
                            <div class="video-item mb-4">
                                <h6>视频 ${index + 1}/${data.videos.length}</h6>
                                <video controls class="mt-2" style="max-width: 100%; max-height: 400px;">
                                    <source src="${video}" type="video/mp4">
                                    您的浏览器不支持视频播放
                                </video>
                            </div>
                        `;
                    });
                    
                    html += `
                            </div>
                        </div>
                    `;
                }
                
                // 显示音频播放器
                if (data.audios && data.audios.length > 0) {
                    html += `
                        <div class="mt-4">
                            <h5>音频预览</h5>
                            <div class="audio-preview-list">
                    `;
                    
                    data.audios.forEach((audio, index) => {
                        html += `
                            <div class="audio-item mb-3">
                                <h6>音频 ${index + 1}/${data.audios.length}</h6>
                                <audio controls class="mt-2" style="width: 100%; max-width: 500px;">
                                    <source src="${audio}" type="audio/mpeg">
                                    您的浏览器不支持音频播放
                                </audio>
                            </div>
                        `;
                    });
                    
                    html += `
                            </div>
                        </div>
                    `;
                }
                
                // 显示文件列表
                if (adofaiData && adofaiData.status === 'success' && adofaiData.files && adofaiData.files.length > 0) {
                    // 确保文件夹排在文件前面（虽然后端已经排序，但前端再确认一下）
                    const sortedFiles = [...adofaiData.files].sort((a, b) => {
                        // 文件夹排在前面
                        if (a.type === 'directory' && b.type !== 'directory') return -1;
                        if (a.type !== 'directory' && b.type === 'directory') return 1;
                        // 同类型按名称排序
                        return a.name.localeCompare(b.name);
                    });
                    
                    html += `
                        <div class="mt-4">
                            <h5>文件列表</h5>
                            <div class="row row-cols-1 row-cols-md-2 g-3 mt-2">
                                ${sortedFiles.map(file => {
                                    // 根据文件类型选择图标
                                    let iconName = 'file';
                                    const typeText = file.type === 'directory' ? '文件夹' : '文件';
                                    
                                    if (file.type === 'directory') {
                                        iconName = 'folder';
                                    } else {
                                        // 根据文件扩展名选择图标
                                        const ext = file.extension || '';
                                        if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) {
                                            iconName = 'file-image';
                                        } else if (['mp4', 'avi', 'mov', 'wmv', 'flv', 'webm'].includes(ext)) {
                                            iconName = 'file-play';
                                        } else if (['mp3', 'wav', 'flac', 'aac', 'ogg'].includes(ext)) {
                                            iconName = 'file-music';
                                        } else if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) {
                                            iconName = 'file-zip';
                                        } else if (['pdf'].includes(ext)) {
                                            iconName = 'file-pdf';
                                        } else if (['doc', 'docx'].includes(ext)) {
                                            iconName = 'file-word';
                                        } else if (['xls', 'xlsx'].includes(ext)) {
                                            iconName = 'file-excel';
                                        } else if (['ppt', 'pptx'].includes(ext)) {
                                            iconName = 'file-ppt';
                                        } else if (['txt', 'md', 'markdown', 'log'].includes(ext)) {
                                            iconName = 'file-text';
                                        } else if (['js', 'css', 'html', 'htm', 'json', 'xml', 'yaml', 'yml', 'ini', 'cfg', 'conf'].includes(ext)) {
                                            iconName = 'file-code';
                                        } else if (['py', 'java', 'c', 'cpp', 'h', 'hpp', 'cs', 'php', 'rb', 'go', 'rs'].includes(ext)) {
                                            iconName = 'file-code';
                                        } else {
                                            iconName = 'file';
                                        }
                                    }
                                    
                                    return `
                                        <div class="col">
                                            <div class="file-item p-3 border rounded shadow-sm">
                                                <div class="d-flex align-items-center">
                                                    <img src="/static/icons/${iconName}.svg" alt="${typeText}" class="file-icon fs-3 me-3" style="width: 32px; height: 32px;">
                                                    <div class="flex-grow-1">
                                                        <div class="file-name">${file.name}</div>
                                                        <div class="file-meta text-sm">
                                                            ${typeText} • ${formatBytes(file.size)}
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        </div>
                    `;
                }
                
                // 总是显示下载按钮
                html += `
                    <div class="mt-4 text-center">
                        <a href="/download/${encodeURIComponent(filename)}" class="btn btn-primary">
                            <i class="bi bi-download"></i> 下载文件
                        </a>
                    </div>
                </div>
                `;
                
                previewContainer.innerHTML = html;
                
                // 如果有图片，初始化图片画廊
                if (data.images && data.images.length > 0) {
                    const gallery = initImageGallery(data.images);
                    const galleryContainer = previewContainer.querySelector('#zip-image-gallery');
                    if (galleryContainer) {
                        galleryContainer.appendChild(gallery);
                    }
                }
            })
            .catch(error => {
                console.error('检查ZIP文件媒体失败:', error);
                previewContainer.innerHTML = `
                    <div class="unsupported-container text-center">
                        <i class="bi bi-file-earmark-zip display-4 text-muted mb-3"></i>
                        <h4>ZIP压缩文件</h4>
                        <p class="text-muted">无法检查文件内容</p>
                        <a href="/download/${encodeURIComponent(filename)}" class="btn btn-primary mt-3">
                            <i class="bi bi-download"></i> 下载文件
                        </a>
                    </div>
                `;
            });
    } else if (ext === 'adofai') {
        // 处理.adofai文件，获取谱面信息
        fetch(`/api/adofai_level_info?filename=${encodeURIComponent(filename)}&file_type=json`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    let html = `
                        <div class="adofai-preview">
                            <h4>Adofai谱面文件信息</h4>
                            <div class="adofai-info">
                                <div class="meta-grid">
                                    <div class="meta-item">
                                        <span class="meta-label">歌曲名称</span>
                                        <span class="meta-value">${data.level_info.song || '未知'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">艺术家</span>
                                        <span class="meta-value">${data.level_info.artist || '未知'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">谱面作者</span>
                                        <span class="meta-value">${data.level_info.author || '未知'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">难度</span>
                                        <span class="meta-value">${data.level_info.difficulty || '未知'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">BPM</span>
                                        <span class="meta-value">${data.level_info.bpm || '未知'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">步数</span>
                                        <span class="meta-value">${data.level_info.steps_count || '0'}步</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">音频文件</span>
                                        <span class="meta-value">${data.audio_file || '无'}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">图片文件数量</span>
                                        <span class="meta-value">${data.image_files ? data.image_files.length : 0}</span>
                                    </div>
                                    <div class="meta-item">
                                        <span class="meta-label">视频文件数量</span>
                                        <span class="meta-value">${data.video_files ? data.video_files.length : 0}</span>
                                    </div>
                                </div>
                            </div>
                            <div class="mt-3 text-center">
                                <a href="/download/${encodeURIComponent(filename)}" class="btn btn-primary">
                                    <i class="bi bi-download"></i> 下载谱面文件
                                </a>
                            </div>
                        </div>
                    `;
                    previewContainer.innerHTML = html;
                } else {
                    previewContainer.innerHTML = `
                        <div class="unsupported-container text-center">
                            <i class="bi bi-file-earmark display-4 text-muted mb-3"></i>
                            <h4>Adofai谱面文件</h4>
                            <p class="text-muted">无法解析谱面信息</p>
                            <a href="/download/${encodeURIComponent(filename)}" class="btn btn-primary mt-3">
                                <i class="bi bi-download"></i> 下载文件
                            </a>
                        </div>
                    `;
                }
            })
            .catch(error => {
                console.error('获取谱面信息失败:', error);
                previewContainer.innerHTML = `
                    <div class="unsupported-container text-center">
                        <i class="bi bi-file-earmark display-4 text-muted mb-3"></i>
                        <h4>Adofai谱面文件</h4>
                        <p class="text-muted">获取谱面信息失败</p>
                        <a href="/download/${encodeURIComponent(filename)}" class="btn btn-primary mt-3">
                            <i class="bi bi-download"></i> 下载文件
                        </a>
                    </div>
                `;
            });
    } else {
        // 其他文件类型的预览逻辑
        let fileTypeMessage = '此文件类型不支持在线预览';
        let fileTypeClass = '';
        
        if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) {
            fileTypeMessage = '压缩文件不支持在线预览，请下载后解压查看';
            fileTypeClass = 'compressed-file';
        } else if (['exe', 'msi', 'dll', 'sys', 'com'].includes(ext)) {
            fileTypeMessage = '可执行文件不支持在线预览，请下载后运行';
            fileTypeClass = 'executable-file';
        } else if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) {
            fileTypeMessage = 'Office文档不支持在线预览，请下载后用相应软件打开';
            fileTypeClass = 'office-file';
        }
        
        previewContainer.innerHTML = `
            <div class="unsupported-container ${fileTypeClass} text-center">
                <i class="bi bi-file-earmark display-4 text-muted mb-3"></i>
                <h4>提示：不支持在线预览</h4>
                <p class="text-muted">${fileTypeMessage}</p>
                <a href="/download/${encodeURIComponent(filename)}" class="btn btn-primary mt-3">
                    <i class="bi bi-download"></i> 下载文件
                </a>
                <div class="mt-4 alert alert-info">
                    <i class="bi bi-info-circle"></i>
                    <strong>文件名：</strong>${decodedFilename}
                    <br>
                    <strong>文件大小：</strong>${document.getElementById('file-size').textContent}
                </div>
            </div>
        `;
    }
}

// 更新活动缩略图
function updateActiveThumbnail(index) {
    const thumbnails = document.querySelectorAll('.thumbnail');
    thumbnails.forEach((thumb, i) => {
        thumb.classList.toggle('active', i === index);
    });
}

// 更新图片信息
function updateImageInfo(index) {
    const imageInfo = document.querySelector('.image-info');
    const images = Array.from(document.querySelectorAll('.thumbnail')).map(thumb => thumb.src);
    if (imageInfo) {
        imageInfo.innerHTML = `<p>${index + 1}/${images.length}</p>`;
    }
}

// 页面初始化
function initPage() {
    // 根据当前页面路径初始化相应功能
    const path = window.location.pathname;
    
    if (path === '/user') {
        initUserPage();
    } else if (path === '/file_detail') {
        initFileDetailPage();
    } else if (path === '/') {
        // 首页初始化
        // 可以添加首页特定功能
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', initPage);

// 导出函数，供其他脚本调用
window.fileShareApp = {
    initPage,
    initUserPage,
    initFileDetailPage,
    initFileUpload,
    loadFiles,
    filterFiles,
    initImageGallery
};