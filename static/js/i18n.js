/**
 * 国际化 (i18n) 模块
 * 支持多语言切换功能
 */

class I18n {
  constructor() {
    this.currentLang = localStorage.getItem('language') || 'zh';
    this.translations = {};
    this.init();
  }

  async init() {
    await this.loadTranslations(this.currentLang);
    this.applyTranslations();
  }

  // 加载翻译文件
  async loadTranslations(lang) {
    try {
      const response = await fetch(`/api/lang/${lang}`);
      if (!response.ok) {
        throw new Error(`Failed to load ${lang} translations`);
      }
      const data = await response.json();
      if (data.status === 'success' && data.language) {
        this.translations = data.language.translations || {};
        this.currentLang = lang;
        localStorage.setItem('language', lang);
      } else {
        throw new Error(data.message || 'Failed to load translations');
      }
    } catch (error) {
      console.error('Error loading translations:', error);
      // 如果加载失败，使用默认的中文
      if (lang !== 'zh') {
        await this.loadTranslations('zh');
      }
    }
  }

  // 切换语言
  async setLanguage(lang) {
    if (lang !== this.currentLang) {
      await this.loadTranslations(lang);
      this.applyTranslations();
      // 触发语言切换事件
      document.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang } }));
    }
  }

  // 获取翻译文本
  t(key, defaultValue = '') {
    const keys = key.split('.');
    let value = this.translations;
    
    for (const k of keys) {
      if (value && typeof value === 'object' && k in value) {
        value = value[k];
      } else {
        return defaultValue || key;
      }
    }
    
    return typeof value === 'string' ? value : (defaultValue || key);
  }

  // 应用翻译到页面元素
  applyTranslations() {
    // 查找所有带有 data-i18n 属性的元素
    const elements = document.querySelectorAll('[data-i18n]');
    elements.forEach(element => {
      const key = element.getAttribute('data-i18n');
      const translation = this.t(key);
      
      // 检查是否有属性翻译
      const attrKey = element.getAttribute('data-i18n-attr');
      if (attrKey) {
        element.setAttribute(attrKey, translation);
      } else {
        element.textContent = translation;
      }
    });

    // 查找所有带有 data-i18n-placeholder 属性的元素
    const placeholderElements = document.querySelectorAll('[data-i18n-placeholder]');
    placeholderElements.forEach(element => {
      const key = element.getAttribute('data-i18n-placeholder');
      element.placeholder = this.t(key);
    });

    // 查找所有带有 data-i18n-title 属性的元素
    const titleElements = document.querySelectorAll('[data-i18n-title]');
    titleElements.forEach(element => {
      const key = element.getAttribute('data-i18n-title');
      element.title = this.t(key);
    });
  }

  // 获取当前语言
  getCurrentLanguage() {
    return this.currentLang;
  }

  // 获取支持的语言列表
  async getSupportedLanguages() {
    try {
      const response = await fetch('/api/languages');
      const data = await response.json();
      
      if (data.status === 'success' && data.languages) {
        return data.languages.map(lang => ({
          code: lang.code,
          name: lang.name,
          flag: lang.flag
        }));
      }
      
      return [
        { code: 'zh', name: '中文', flag: '🇨🇳' },
        { code: 'en', name: 'English', flag: '🇺🇸' }
      ];
    } catch (error) {
      console.error('Error loading supported languages:', error);
      return [
        { code: 'zh', name: '中文', flag: '🇨🇳' },
        { code: 'en', name: 'English', flag: '🇺🇸' }
      ];
    }
  }
}

// 创建全局i18n实例
const i18n = new I18n();

// 页面加载完成后应用翻译
document.addEventListener('DOMContentLoaded', () => {
  i18n.applyTranslations();
});

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
  module.exports = I18n;
}
