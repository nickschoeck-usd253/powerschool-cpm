const vscode = require('vscode');
const https = require('https');

function generateMultipartData(fields, boundary) {
    let data = '';
    for (const [name, value] of Object.entries(fields)) {
        data += `--${boundary}\r\n`;
        data += `Content-Disposition: form-data; name="${name}"\r\n\r\n`;
        data += `${value}\r\n`;
    }
    data += `--${boundary}--\r\n`;
    return data;
}

class PowerSchoolAPI {
    constructor() {
        this.baseUrl = '';
        this.username = '';
        this.password = '';

        this.sessionValid = false;
        this.lastSessionCheck = 0;
        this.sessionCheckInterval = 5 * 60 * 1000;
        this.cookies = new Map();

        this.contentIdCache = new Map();
        this.workspaceState = null;
    }

    setWorkspaceState(state) {
        this.workspaceState = state;
        this.loadCacheFromStorage();
    }

    loadCacheFromStorage() {
        if (!this.workspaceState) return;
        const stored = this.workspaceState.get('ps-cpm-contentIdCache', {});
        this.contentIdCache = new Map(Object.entries(stored));
    }

    saveCacheToStorage() {
        if (!this.workspaceState) return;
        this.workspaceState.update('ps-cpm-contentIdCache', Object.fromEntries(this.contentIdCache));
    }

    initialize() {
        const config = vscode.workspace.getConfiguration('ps-vscode-cpm');
        this.baseUrl = config.get('serverUrl', '').replace(/\/$/, '');
        this.username = config.get('username');
        this.password = config.get('password');

        if (!this.baseUrl) {
            throw new Error('PowerSchool server URL not configured. Please set ps-vscode-cpm.serverUrl in settings.');
        }
    }

    clearAuth() {
        this.sessionValid = false;
        this.lastSessionCheck = 0;
        this.cookies.clear();
    }

    // ── HTTP layer ──────────────────────────────────────────────────────────

    /**
     * @param {string} path
     * @param {string} method
     * @param {Record<string, string>} [extraHeaders]
     */
    _httpOptions(path, method, extraHeaders = {}) {
        return {
            hostname: new URL(this.baseUrl).hostname,
            port: 443,
            path,
            method,
            rejectUnauthorized: false,
            headers: {
                'User-Agent': 'ps-vscode-cpm/2.5.0',
                ...extraHeaders
            }
        };
    }

    /**
     * All HTTP requests go through here. Drains the response body, fires resolve
     * exactly once (on 'end') and reject exactly once (on 'error' from either the
     * request socket or the response stream). Using res.once prevents the double-
     * settlement that would occur if both 'error' and 'end' fired in the same tick.
     * @param {import('https').RequestOptions & { headers: Record<string, string | number> }} options
     * @param {string | null} [body]
     */
    _httpRequest(options, body = null) {
        return new Promise((resolve, reject) => {
            if (body !== null) {
                options.headers['Content-Length'] = Buffer.byteLength(body);
            }

            const req = https.request(options, (res) => {
                /** @type {Buffer[]} */
                const chunks = [];
                res.on('data', chunk => chunks.push(chunk));
                res.once('error', reject);
                res.once('end', () => resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: Buffer.concat(chunks).toString()
                }));
            });

            req.once('error', reject);
            if (body !== null) req.write(body);
            req.end();
        });
    }

    // ── Cookie management ───────────────────────────────────────────────────

    parseCookies(cookieHeaders) {
        if (!cookieHeaders) return;
        for (const cookie of cookieHeaders) {
            const [nameValue] = cookie.split(';');
            const eqIdx = nameValue.indexOf('=');
            if (eqIdx === -1) continue;
            const name = nameValue.slice(0, eqIdx).trim();
            const value = nameValue.slice(eqIdx + 1).trim();
            if (name) {
                this.cookies.set(name, value);
            }
        }
    }

    getCookieHeader() {
        const parts = [];
        for (const [name, value] of this.cookies) {
            parts.push(`${name}=${value}`);
        }
        return parts.join('; ');
    }

    // ── Session authentication ──────────────────────────────────────────────

    async getLoginPage() {
        const opts = this._httpOptions('/admin/pw.html', 'GET');
        const res = await this._httpRequest(opts);
        this.parseCookies(res.headers['set-cookie']);
    }

    async submitLogin() {
        const postData = new URLSearchParams({
            username: this.username,
            password: this.password,
            ldappassword: this.password,
            request_locale: 'en_US'
        }).toString();

        const opts = this._httpOptions('/admin/home.html', 'POST', {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': this.getCookieHeader(),
            'Referer': `${this.baseUrl}/admin/pw.html`
        });

        const res = await this._httpRequest(opts, postData);
        this.parseCookies(res.headers['set-cookie']);

        if (res.statusCode === 302) {
            this.sessionValid = true;
            this.lastSessionCheck = Date.now();
            return true;
        }

        if (res.statusCode === 200) {
            // Some PS versions return 200 on success rather than redirecting.
            // Verify by probing a page that requires auth.
            return this.checkSession();
        }

        return false;
    }

    async checkSession() {
        if (this.sessionValid && (Date.now() - this.lastSessionCheck < this.sessionCheckInterval)) {
            return true;
        }

        const opts = this._httpOptions('/admin/customization/home.html', 'GET', {
            'Cookie': this.getCookieHeader()
        });

        try {
            const res = await this._httpRequest(opts);
            this.lastSessionCheck = Date.now();
            this.parseCookies(res.headers['set-cookie']);
            this.sessionValid = res.statusCode === 200;
            return this.sessionValid;
        } catch {
            this.sessionValid = false;
            return false;
        }
    }

    async ensureSessionAuth() {
        let isLoggedIn = await this.checkSession();

        if (!isLoggedIn) {
            if (!this.username || !this.password) {
                throw new Error('PowerSchool session credentials missing. Please configure username and password in VS Code settings.');
            }
            await this.getLoginPage();
            isLoggedIn = await this.submitLogin();
            if (!isLoggedIn) {
                throw new Error('PowerSchool login failed. Please check your credentials.');
            }
        }

        return true;
    }

    async ensureAuthenticated() {
        await this.ensureSessionAuth();
    }

    getAuthHeaders() {
        return { 'Cookie': this.getCookieHeader() };
    }

    // ── API requests ────────────────────────────────────────────────────────

    async makeRequest(endpoint, method = 'GET', data = null) {
        await this.ensureAuthenticated();

        const body = data ? (typeof data === 'string' ? data : JSON.stringify(data)) : null;
        /** @type {Record<string, string>} */
        const extraHeaders = {
            'Accept': 'application/json',
            ...this.getAuthHeaders()
        };

        if (body) {
            extraHeaders['Content-Type'] = typeof data === 'string'
                ? 'application/x-www-form-urlencoded'
                : 'application/json';
        }

        const opts = this._httpOptions(endpoint, method, extraHeaders);
        const res = await this._httpRequest(opts, body);

        if (res.statusCode === 403) {
            throw new Error('Insufficient PowerSchool permissions. Ensure your account has CPM admin access.');
        }

        try {
            return { statusCode: res.statusCode, data: res.body ? JSON.parse(res.body) : {} };
        } catch {
            return { statusCode: res.statusCode, data: res.body };
        }
    }

    async getFolderTree(path = '/', maxDepth = 1) {
        const queryParams = new URLSearchParams({ path, maxDepth: maxDepth.toString() });
        const response = await this.makeRequest(`/ws/cpm/tree?${queryParams}`);

        if (response.statusCode !== 200) {
            throw new Error(`Failed to get folder tree: HTTP ${response.statusCode}`);
        }
        return response.data;
    }

    /**
     * Downloads and parses plugin mappings from a server-generated JSON file.
     * The JSON file contains tlist_sql template that generates plugin metadata.
     * Uses direct HTTP access (not /ws/cpm/builtintext) to get the executed JSON.
     * Expected format: [{ "path": "/path/to/file.html", "plugin": "PluginName", "enabled": "1" }]
     */
    async getPluginMappingsFromJson(jsonFilePath = '/vscode_cpm/plugin_data.json') {
        try {
            const response = await this.makeRequest(jsonFilePath);
            if (response.statusCode !== 200) return null;

            let pluginData;
            try {
                pluginData = typeof response.data === 'string'
                    ? JSON.parse(response.data)
                    : response.data;
            } catch {
                return null;
            }

            if (Array.isArray(pluginData)) {
                const normalized = {};
                for (const item of pluginData) {
                    if (item.path) {
                        normalized[item.path] = {
                            plugin: item.plugin || item.pluginName || 'Unknown',
                            enabled: item.enabled !== false
                        };
                    }
                }
                pluginData = normalized;
            }

            return pluginData;
        } catch {
            return null;
        }
    }

    /**
     * Returns the file listing for a schema root.
     * GET /ws/cpm/content?root=...
     * Mirrors cpmServices.js getContentRoot() (lines 690-703).
     * @param {string} root - 'queries_root' or 'user_schema_root'
     */
    async getSchemaRootTree(root) {
        const queryParams = new URLSearchParams({ root });
        const endpoint = `/ws/cpm/content?${queryParams.toString()}`;
        const response = await this.makeRequest(endpoint);
        if (response.statusCode !== 200) {
            throw new Error(`Failed to get schema root tree: HTTP ${response.statusCode}`);
        }
        return response.data;
    }

    /**
     * Fetches content for a file in a schema root.
     * GET /ws/cpm/customresource?path=...&root=...
     * Mirrors cpmServices.js getNonWebContent() (lines 734-762).
     * @param {string} filePath - File path within the schema root
     * @param {string} root - 'queries_root' or 'user_schema_root'
     * @returns {Promise<{content: string, isCustom: boolean, activeCustomContentId: number|null}>}
     */
    async getSchemaFileContent(filePath, root) {
        const queryParams = new URLSearchParams({ path: filePath, root });
        const endpoint = `/ws/cpm/customresource?${queryParams.toString()}`;
        const response = await this.makeRequest(endpoint);
        if (response.statusCode !== 200) {
            throw new Error(`Failed to get schema file: HTTP ${response.statusCode}`);
        }
        const result = /** @type {any} */ (response.data);
        const content = result.activeCustomText || result.builtInText || '';
        const customContentId = result.activeCustomContentId || null;
        if (customContentId) {
            this.contentIdCache.set(filePath, customContentId);
            this.saveCacheToStorage();
        }
        return { content, isCustom: result.isCustom === true, activeCustomContentId: customContentId };
    }

    async downloadFileContent(filePath) {
        const result = await this.downloadFileWithMetadata(filePath);
        return result.content;
    }

    /**
     * Downloads file content along with metadata (customContentId, etc.)
     * Used for conflict detection during sync operations.
     * @param {string} filePath - Remote path to the file
     * @returns {Promise<{content: string, customContentId: number|null, isCustom: boolean, rawResponse: object|null}>}
     *
     * Priority order for content fields:
     * 1. builtInText — built-in files (skip if it's the "not available" placeholder)
     * 2. customPageContent — custom files (LoadFolderInfo=false path)
     * 3. activeCustomText — customized files (skip if it's the "not available" placeholder)
     */
    async downloadFileWithMetadata(filePath) {
        const queryParams = new URLSearchParams({ LoadFolderInfo: 'false', path: filePath });
        await this.ensureAuthenticated();

        const opts = this._httpOptions(`/ws/cpm/builtintext?${queryParams}`, 'GET', {
            'Referer': `${this.baseUrl}/admin/customization/home.html`,
            'Accept': 'application/json',
            ...this.getAuthHeaders()
        });

        const res = await this._httpRequest(opts);

        if (res.statusCode === 403) {
            throw new Error('Insufficient PowerSchool permissions to access this file.');
        }
        if (res.statusCode !== 200) {
            throw new Error(`Download failed: HTTP ${res.statusCode}`);
        }

        try {
            const result = JSON.parse(res.body);

            let content = '';
            if (result.builtInText && !result.builtInText.startsWith('Built in file')) {
                content = result.builtInText;
            } else if (result.customPageContent) {
                content = result.customPageContent;
            } else if (result.activeCustomText && !result.activeCustomText.startsWith('Active custom file')) {
                content = result.activeCustomText;
            }

            // Fallback: if no active content yet but version history exists, use first entry
            let customContentId = result.activeCustomContentId || null;
            if (!customContentId && result.versionAssetContentIds?.length > 0) {
                customContentId = result.versionAssetContentIds[0];
            }
            if (customContentId) {
                this.contentIdCache.set(filePath, customContentId);
                this.saveCacheToStorage();
            }

            return { content, customContentId, isCustom: result.isCustom === true, rawResponse: result };
        } catch {
            return { content: res.body, customContentId: null, isCustom: false, rawResponse: null };
        }
    }

    async uploadFileContent(filePath, content, { isCustom = true, builtInContent = '' } = {}) {
        await this.ensureAuthenticated();

        if (!isCustom) {
            await this.customizeAsset(filePath, builtInContent);
        }

        const cachedId = this.contentIdCache.get(filePath);
        if (cachedId) {
            try {
                return await this._doUpload(filePath, content, cachedId);
            } catch {
                this.contentIdCache.delete(filePath);
            }
        }

        try {
            const fileInfo = await this.downloadFileInfo(filePath);
            const customContentId = fileInfo?.activeCustomContentId;
            if (customContentId) {
                this.contentIdCache.set(filePath, customContentId);
                this.saveCacheToStorage();
                return await this._doUpload(filePath, content, customContentId);
            }
        } catch {
            // file doesn't exist on PowerSchool yet — treat as new
        }

        return this._doUpload(filePath, content, 0);
    }

    async _doUpload(filePath, content, customContentId) {
        const keyPath = filePath
            .replace(/^\/+/, '')
            .replace(/\//g, '.')
            .replace(/\.(html|htm|js|css|txt)$/i, '');

        const boundary = `----formdata-node-${Math.random().toString(36).substr(2, 16)}`;
        const body = generateMultipartData({
            customContentId,
            customContent: content,
            customContentPath: filePath,
            keyPath,
            keyValueMap: 'null',
            publish: 'true'
        }, boundary);

        const opts = this._httpOptions('/ws/cpm/customPageContent', 'POST', {
            'Referer': `${this.baseUrl}/admin/customization/home.html`,
            'Accept': 'application/json',
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
            ...this.getAuthHeaders()
        });

        const res = await this._httpRequest(opts, body);

        if (res.statusCode === 403) {
            throw new Error('Insufficient PowerSchool permissions to publish this file.');
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
            throw new Error(`Upload failed: HTTP ${res.statusCode}`);
        }

        let result;
        try {
            result = JSON.parse(res.body);
        } catch {
            return { success: true, raw: res.body };
        }

        if (result.returnMessage?.includes('system error') || result.returnMessage?.includes('could not be saved')) {
            throw new Error(result.returnMessage);
        }
        if (result.activeCustomContentId) {
            this.contentIdCache.set(filePath, result.activeCustomContentId);
            this.saveCacheToStorage();
        }
        return result;
    }

    async downloadFileInfo(filePath) {
        const queryParams = new URLSearchParams({ LoadFolderInfo: 'true', path: filePath });
        await this.ensureAuthenticated();

        const opts = this._httpOptions(`/ws/cpm/builtintext?${queryParams}`, 'GET', {
            'Referer': `${this.baseUrl}/admin/customization/home.html`,
            'Accept': 'application/json',
            ...this.getAuthHeaders()
        });

        const res = await this._httpRequest(opts);

        if (res.statusCode !== 200) {
            throw new Error(`File info request failed: HTTP ${res.statusCode}`);
        }

        try {
            const fileInfo = JSON.parse(res.body);
            if (fileInfo.activeCustomContentId) {
                this.contentIdCache.set(filePath, fileInfo.activeCustomContentId);
                this.saveCacheToStorage();
            }
            return fileInfo;
        } catch {
            throw new Error('Failed to parse file info response');
        }
    }

    /**
     * Promotes a built-in asset to a customizable one by creating an initial draft.
     * Must be called before the first customPageContent save when isCustom = false.
     * Mirrors cpmServices.js customizeAsset() (lines 802-828).
     * @param {string} filePath - Remote path (e.g., /admin/home.html)
     * @param {string} builtInContent - The builtInText from the prior builtintext response
     * @returns {Promise<{activeCustomContentId: number}>}
     */
    async customizeAsset(filePath, builtInContent) {
        await this.ensureAuthenticated();

        const fileName = filePath.split('/').pop() || '';
        const folderPath = filePath.substring(0, filePath.lastIndexOf('/'));
        const postData = new URLSearchParams({
            initialAssetContent: builtInContent || '',
            newAssetName: fileName,
            newAssetPath: folderPath,
            newAssetType: 'file'
        }).toString();

        const opts = this._httpOptions('/ws/cpm/customizeAsset', 'POST', {
            'Referer': `${this.baseUrl}/admin/customization/home.html`,
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            ...this.getAuthHeaders()
        });

        const res = await this._httpRequest(opts, postData);

        if (res.statusCode === 403) {
            throw new Error('Insufficient PowerSchool permissions to customize this file.');
        }
        if (res.statusCode !== 200) {
            throw new Error(`customizeAsset failed: HTTP ${res.statusCode}`);
        }

        try {
            const result = JSON.parse(res.body);
            if (result.activeCustomContentId) {
                this.contentIdCache.set(filePath, result.activeCustomContentId);
                this.saveCacheToStorage();
            }
            return result;
        } catch {
            throw new Error('Failed to parse customizeAsset response');
        }
    }

    async verifyUpload(filePath) {
        try {
            return await this.downloadFileContent(filePath);
        } catch (error) {
            throw new Error(`Verification failed: ${error.message}`);
        }
    }

    async checkFileExists(filePath) {
        try {
            await this.downloadFileInfo(filePath);
            return true;
        } catch {
            return false;
        }
    }

    async createNewFile(filePath, content) {
        return this.uploadFileContent(filePath, content);
    }

    async updateExistingFileContent(filePath, content) {
        return this.uploadFileContent(filePath, content);
    }

    /**
     * Delete a custom file from PowerSchool.
     * If the file is a built-in file that was customized, this removes the customization.
     * @param {string} filePath - Remote path to the file (e.g., /admin/custom.html)
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async deleteFile(filePath) {
        await this.ensureAuthenticated();

        const postData = `path=${encodeURIComponent(filePath)}`;
        const opts = this._httpOptions('/ws/cpm/deleteFile', 'POST', {
            'Referer': `${this.baseUrl}/admin/customization/home.html`,
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            ...this.getAuthHeaders()
        });

        const res = await this._httpRequest(opts, postData);

        let result;
        try {
            result = JSON.parse(res.body);
        } catch {
            throw new Error('Failed to parse delete response');
        }

        if (res.statusCode === 200) {
            if (result.returnMessage === 'The file was deleted sucessfully') {
                // Note: PowerSchool has a typo in "sucessfully" — matching their API
                this.contentIdCache.delete(filePath);
                this.saveCacheToStorage();
                return { success: true, message: 'File deleted successfully' };
            }
            if (result.returnMessage) throw new Error(result.returnMessage);
            return { success: true, message: 'File deleted' };
        }

        if (res.statusCode === 400) {
            throw new Error(result.message || 'File could not be deleted');
        }

        throw new Error(`Delete failed: HTTP ${res.statusCode}`);
    }
}

module.exports = { PowerSchoolAPI };
