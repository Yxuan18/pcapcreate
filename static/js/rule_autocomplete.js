/**
 * Tab 替换 +（可选）配置弹窗。
 *
 * 使用方式（模板里）：
 *   initRuleAutocomplete('file_content_edit', checkContentCompliance, { layer, configButtonId: 'tab_replace_cfg_btn' })
 *
 * 规则存储：localStorage key = tstools_tab_replace_rules_v1
 * 规则格式：[{from:"md:http", to:"metadata:service http; "}, {from:"re:/\\s+/g", to:" "}, ...]
 */

const TAB_REPLACE_STORAGE_KEY = 'tstools_tab_replace_rules_v1';

// 默认的“用户可编辑”规则（用于 localStorage 初始化/重置）。
// 大规模替换（从 TamperMonkeys/Suricata_bot_beta 的 REPLACE_DICTIONARY 移植）在 BUILTIN_REPLACE_DICTIONARY 里，默认总是启用。
const DEFAULT_TAB_REPLACE_RULES = [
    {"from":"md:http","to":"metadata:service http; "},
    {"from":"md:tcp","to":"metadata:service tcp; "},
    {"from":"md:udp","to":"metadata:service udp; "},
    {"from":"md:icmp","to":"metadata:service icmp; "},
];

// 内置替换库：来源于 TamperMonkeys/Suricata_bot_beta-v1.1.03.user.js 的 REPLACE_DICTIONARY
// 说明：这部分不走 localStorage，避免大量正则序列化/转义问题；仅用于在 Tab 时快速展开/净化规则文本。
const BUILTIN_REPLACE_DICTIONARY = [
    // 基础简写替换
    [/fl(ow)?:s/g, 'flow:to_server; http.uri; content:""; metadata:service http;'],
    [/fl(ow)?:c/g, 'flow:to_client'],
    [/^fl(ow)?:c$/g, 'flow:to_client; content:""; metadata:service http;'],
    [/;\s?b64d/g, '; content:""; base64_decode:offset 0, relative; base64_data; content:"";'],
    [/(nocase; )\1+/g, '$1'],
    [/uricontent/g, 'http.uri; content'],
    [/reqb/g, 'http.request_body; content:"";'],
    [/reql/g, 'http.request_line;'],
    [/;\s?ct/g, '; content:""; '],
    [/;\s?pr/g, String.raw`; pcre:"/\b/";`],

    // 复杂漏洞探测特征替换
    [/\x3a\x3a\x2a\s?/g, String.raw`[^\x0d\x0a]*?`],
    [/\x3a\x3a\x22\s?/g, String.raw`\x22\x3a\s?\x22[^\x0a\x0d\x22]*?`],
    [/\x3a\x3aosi\s?/g, String.raw`[^\x0d\x0a]*?(\x3b|\x60|\x24\x28|\x7c{1,2})\x20?\b(open|echo|ps|cd|n?cat|wget|curl|certutil|ifconfig|ipconfig|systeminfo|shutdown|taskkill|whoami|netstat|utelnetd|reboot|net\x20user|ping|bash|poweroff|telnet|ls|id|ip|pwd|dir|nc|touch|mkdir|mkfifo|expr|mknod)\b`],
    [/\x3a\x3asqli\s?/g, String.raw`[^\x0d\x0a\x26]*?\b(select|union|and|length|update|order|insert|\/\*\*|delete|updatexml|extractvalue|substr|convert)\b[^\x0d\x0a\x26]*?\b(sleep|by|version|from|where|char|chr|into|set|md5|user|concat|sys\x2efn_sqlvarbasetostr)|(\bWAITFOR\b[\s\S]*\bDELAY\b)`],
    [/\x3a\x3axss\s?/g, String.raw`[^\x0a\x0d\x26]*?\x3c\b(script|iframe|img|svg|div|bgsound|link|input|body|table|base|embed|href)\b[^\x0a\x0d\x26]*?\b((onload|oncontextmenu|fromcharcode|alert|write|eval|confirm|expression|prompt|style|src|xss|location)\b|\bon)\s*?[\x3a\x28\x3d][^\x0a\x0d\x26]*\x3e`],
    [/\x3a\x3axxe\s?/g, String.raw`<\!(entity|doctype)\b[^\x0a\x0d]*?(system|public)\b`],
    [/\x3a\x3apath\s?/g, String.raw`[^\x0a\x0d\x26]*?(\x2e{1,}\x3b{0,}[\x5c\x2f]+){2,}`],
    [/\x3a\x3assrf\s?/g, String.raw`(file|https?|ftp)\x3a\x2f\x2f(127\x2e0\x2e0\x2e1|localhost|(192|172|10)\x2e)`],
    [/\x3a\x3ajava?\s?/g, String.raw`[^\x0a\x0d]*?((getConstructor\x28\x5bClass[\x2e\x2f]forName\x28\x22java[\x2e\x2f]lang[\x2e\x2f]String\x22\x29\x5d\x29\x2enewInstance\x28\x5b\x22\b(ipconfig|systeminfo|shutdown|taskkill|whoami|ifconfig|netstat|reboot|net\suser|bash|poweroff|shutdown|etc)\b)\x22\x5d\x29\x2etoString\x28\x29|java[\x2e\x2f]lang[\x2e\x2f]runtime[\s\S]+getruntime)`],
    [/\x3a\x3aphp\s?/g, String.raw`\x3c\x3fphp\b[\x20-\x80\x0a\x0d]*?(\b(preg_replace|assert|call_user_func|call_user_func_array|create_function|ob_start|array_map|exec|system|popen|passthru|proc_open|pcntl_exec|shell_exec|curl_exec|curl_multi_exec|escapeshellcmd|phpinfo|file_get_contents|function_exists|file_put_contents|readfile|unlink|fopen|file|fgets|readdir|rmdir|fread|fwrite|fgetc|fgetss|fpassthru|eval|print_r)\x28|\x28\x24_)|\beval\x28\x24`],
    [/\x3a\x3ayiiu\s?/g, String.raw`[^\x0a\x0d\x26]*?\w{50,}?`],

    // HTTP 头部控制
    [/no[_-]r(eferer)?/g, String.raw`http.header; content:!"Referer|3A|";`],
    [/no[_-]c(ookie)?/g, String.raw`http.header; content:!"Cookie|3A|";`],
    [/up[_-]a(sp)?/g, String.raw`http.header; content:"multipart/form-data"; nocase; http.request_body; pcre:"/\bfilename\x3d\x22[^\x0d\x0a\x2e]*?\x2e(aspx?|ashx)\x22/i";`],
    [/up[_-]j(sp)?/g, String.raw`http.header; content:"multipart/form-data"; nocase; http.request_body; pcre:"/\bfilename\x3d\x22[^\x0d\x0a\x2e]*?\x2ejspx?\x22/i";`],
    [/up[_-]p(hp)?/g, String.raw`http.header; content:"multipart/form-data"; nocase; http.request_body; pcre:"/\bfilename\x3d\x22[^\x0d\x0a\x2e]*?\x2e(php\d?|pht(ml)?)\x22/i";`],

    // 格式净化与常见响应
    [/  +/g, ' '], // 统一空格（注意：这里是 NBSP）
    [/h(ttp.)?(?!stat_code)st/g, 'http.stat_code; content:"200"; '],
    [/\x3a\x3axp(ath)?\s?/g, String.raw`XPATH syntax error:`],
    [/\x3a\x3aint\s?/g, String.raw`转换成数据类型 int 时失败`],
    [/\x3a\x3awin\s?/g, String.raw`; for 16-bit app support`],
    [/\x3a\x3alin\s?/g, String.raw`/root:/bin/bash`],
    [/h(ttp.)?hd/g, 'http.header; content:""; '],
    [/h(ttp.)?ct/g, 'http.content_type; content:""; '],
    [/(h(ttp.)?bd|resb)/g, 'http.response_body; content:""; '],
];

// ===== Hex Encoding (from Suricata_bot_beta processHexEncoding) =====
const SNORT_NO_ENCODE_CHARS = new Set([
    ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    '/', '=', '-', '_', '.', '~', '@', '!', '$', '&', '(', ')', '*', '+', ',', ' ',
]);

function _isChineseChar(ch) {
    return /[\u4e00-\u9fa5]/.test(ch);
}

/**
 * 将字符串转换为 Snort content 的十六进制混合格式：
 * - 白名单字符（英文/数字/部分符号/空格/中文）保持原样
 * - 其他字符以 |xx xx| 形式输出
 */
function toSnortHex(content) {
    const result = [];
    let plainBuffer = '';
    let hexBuffer = '';

    for (const char of content) {
        if (SNORT_NO_ENCODE_CHARS.has(char) || _isChineseChar(char)) {
            if (hexBuffer) {
                result.push(`|${hexBuffer}|`);
                hexBuffer = '';
            }
            plainBuffer += char;
        } else {
            if (plainBuffer) {
                result.push(plainBuffer);
                plainBuffer = '';
            }
            const hex = char.charCodeAt(0).toString(16).padStart(2, '0');
            hexBuffer += (hexBuffer ? ' ' : '') + hex;
        }
    }

    if (plainBuffer) result.push(plainBuffer);
    if (hexBuffer) result.push(`|${hexBuffer}|`);

    return result.join('');
}

/**
 * 将规则文本中 content:"..."; 的内容按 Snort 十六进制格式编码。
 * - 已包含 |aa bb| 的 content 会跳过，避免重复编码导致乱码
 * - 只处理看起来像 content 块的片段（尽量避免误伤）
 */
function processHexEncoding(text) {
    // 与 TamperMonkeys 脚本保持一致的匹配边界：到下一个关键字段前停止
    const pmRegex = /(content:")(.*?)(";)(?=\s*(?:content:|nocase|depth|offset|distance|within|fast_pattern|http\x2e|pcre\x3a|\bpr\x3a?|flowbits:|sid:|rev:|classtype:|reference:|metadata:|base64_|url_|$|\x29))/gi;

    return text.replace(pmRegex, (match, prefix, content, suffix) => {
        if (/\|[0-9a-fA-F\s]+\|/.test(content)) return match;
        return prefix + toSnortHex(content) + suffix;
    });
}

function _parseRuleFrom(fromValue) {
    if (typeof fromValue !== 'string') return null;
    if (!fromValue.startsWith('re:/')) return fromValue;
    // 形如 re:/abc/gi
    const rest = fromValue.slice(4);
    const lastSlash = rest.lastIndexOf('/');
    if (lastSlash <= 0) return null;
    const pattern = rest.slice(0, lastSlash);
    const flags = rest.slice(lastSlash + 1);
    try {
        return new RegExp(pattern, flags);
    } catch (e) {
        return null;
    }
}

function loadTabReplaceRules() {
    try {
        const raw = localStorage.getItem(TAB_REPLACE_STORAGE_KEY);
        if (!raw) return DEFAULT_TAB_REPLACE_RULES;
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return DEFAULT_TAB_REPLACE_RULES;
        return parsed;
    } catch (e) {
        return DEFAULT_TAB_REPLACE_RULES;
    }
}

function saveTabReplaceRules(rules) {
    localStorage.setItem(TAB_REPLACE_STORAGE_KEY, JSON.stringify(rules, null, 2));
}

function applyTabReplace(text) {
    const rules = loadTabReplaceRules();
    let out = text;
    let changed = false;
    // 先应用内置大字典（正则替换）
    for (const [regex, replacement] of BUILTIN_REPLACE_DICTIONARY) {
        const next = out.replace(regex, replacement);
        if (next !== out) changed = true;
        out = next;
    }
    // 再处理 content:"..." 的 hex 编码
    {
        const next = processHexEncoding(out);
        if (next !== out) changed = true;
        out = next;
    }
    for (const rule of rules) {
        if (!rule || typeof rule !== 'object') continue;
        const from = _parseRuleFrom(rule.from);
        const to = (typeof rule.to === 'string') ? rule.to : '';
        if (!from) continue;
        if (from instanceof RegExp) {
            const next = out.replace(from, to);
            if (next !== out) changed = true;
            out = next;
        } else {
            if (out.includes(from)) {
                out = out.split(from).join(to);
                changed = true;
            }
        }
    }
    return { out, changed };
}

function getLineRange(value, pos) {
    const start = value.lastIndexOf('\n', pos - 1) + 1;
    const endIdx = value.indexOf('\n', pos);
    const end = endIdx === -1 ? value.length : endIdx;
    return { start, end };
}

function initRuleAutocomplete(textareaId, complianceCheckCallback, options) {
    const textarea = document.getElementById(textareaId);
    if (!textarea) return;

    const opts = options || {};
    const layer = opts.layer; // 可选：layui layer，用于配置弹窗
    const configButtonId = opts.configButtonId;

    textarea.addEventListener('keydown', function (event) {
        if (event.key !== 'Tab') return;
        // 仅在编辑区按 Tab 触发替换，阻止焦点跳走
        event.preventDefault();

        const value = textarea.value || '';
        const selStart = textarea.selectionStart || 0;
        const selEnd = textarea.selectionEnd || 0;

        if (selEnd > selStart) {
            const selected = value.slice(selStart, selEnd);
            const { out, changed } = applyTabReplace(selected);
            if (!changed) {
                // 没匹配到就插入两个空格作为缩进（更符合编辑习惯）
                const insert = '  ';
                textarea.value = value.slice(0, selStart) + insert + value.slice(selEnd);
                textarea.selectionStart = textarea.selectionEnd = selStart + insert.length;
            } else {
                textarea.value = value.slice(0, selStart) + out + value.slice(selEnd);
                textarea.selectionStart = textarea.selectionEnd = selStart + out.length;
            }
        } else {
            const { start, end } = getLineRange(value, selStart);
            const line = value.slice(start, end);
            const { out, changed } = applyTabReplace(line);
            if (!changed) {
                const insert = '  ';
                textarea.value = value.slice(0, selStart) + insert + value.slice(selStart);
                textarea.selectionStart = textarea.selectionEnd = selStart + insert.length;
            } else {
                textarea.value = value.slice(0, start) + out + value.slice(end);
                const newPos = Math.min(start + out.length, textarea.value.length);
                textarea.selectionStart = textarea.selectionEnd = newPos;
            }
        }

        if (typeof complianceCheckCallback === 'function') {
            complianceCheckCallback();
        }
    });

    if (configButtonId && layer && typeof layer.open === 'function') {
        const btn = document.getElementById(configButtonId);
        if (btn) {
            btn.addEventListener('click', function () {
                const current = loadTabReplaceRules();
                layer.open({
                    type: 1,
                    title: 'Tab 替换配置（JSON 数组）',
                    area: ['720px', '520px'],
                    shadeClose: true,
                    content: `
                        <div style="padding: 16px;">
                            <div style="margin-bottom: 10px; color:#666; font-size:12px;">
                                格式示例：{"from":"md:http","to":"metadata:service http; "} 或 {"from":"re:/\\\\s+/g","to":" "}<br/>
                                在编辑区按 Tab，将对选中内容或当前行应用替换。
                            </div>
                            <textarea id="tab_replace_cfg_textarea" class="code-textarea" style="height:340px;"></textarea>
                            <div style="display:flex; gap:10px; justify-content:flex-end; margin-top:12px;">
                                <button type="button" class="layui-btn layui-btn-primary" id="tab_replace_cfg_reset">重置默认</button>
                                <button type="button" class="layui-btn layui-btn-normal" id="tab_replace_cfg_save">保存</button>
                            </div>
                        </div>
                    `
                });

                // layer.open 的 DOM 已渲染
                setTimeout(function () {
                    const ta = document.getElementById('tab_replace_cfg_textarea');
                    const btnSave = document.getElementById('tab_replace_cfg_save');
                    const btnReset = document.getElementById('tab_replace_cfg_reset');

                    ta.value = JSON.stringify(current, null, 2);

                    btnReset.addEventListener('click', function () {
                        ta.value = JSON.stringify(DEFAULT_TAB_REPLACE_RULES, null, 2);
                    });
                    btnSave.addEventListener('click', function () {
                        try {
                            const parsed = JSON.parse(ta.value);
                            if (!Array.isArray(parsed)) throw new Error('必须是数组');
                            saveTabReplaceRules(parsed);
                            layer.msg('已保存 Tab 替换配置', {icon: 1, time: 1200});
                            layer.closeAll('page');
                        } catch (e) {
                            layer.msg('配置解析失败：' + (e && e.message ? e.message : e), {icon: 2, time: 2000});
                        }
                    });
                }, 0);
            });
        }
    }
}

// Export for global use
window.initRuleAutocomplete = initRuleAutocomplete;
