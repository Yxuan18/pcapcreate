/* ═══════════════════════════════════════════════════════════════
   SHARE CARD MODULE
   生成分享卡片：预览 + QR码 + PNG下载
══════════════════════════════════════════════════════════════ */

var _shareStyle = 'dark';
var _previewRendered = false;

function _esc(v) {
    return String(v != null ? v : '')
        .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;');
}

function _fmt(v, digits) {
    if (v == null || Number.isNaN(Number(v))) return '--';
    return Number(v).toFixed(digits != null ? digits : 2);
}

function _trendClass(v) {
    if (v == null) return 'neutral';
    var n = Number(v);
    if (n > 0) return 'up'; if (n < 0) return 'down'; return 'neutral';
}

function _trendSign(v, pct) {
    if (v == null || Number.isNaN(Number(v))) return '--';
    var n = Number(v);
    var sign = n > 0 ? '+' : '';
    var val = pct ? (n * 100).toFixed(2) + '%' : n.toFixed(2);
    return sign + val;
}

function _buildShareCard(data, opts) {
    var style = opts.style || 'dark';
    var title = opts.title || '一轩资产日报';
    var sub = opts.sub || '';
    var qrUrl = opts.qrUrl || window.location.href;

    var tokens = {
        dark: {
            bg: 'linear-gradient(145deg, #050810 0%, #0d1a2e 50%, #050810 100%)',
            cardBg: 'rgba(17,28,48,0.9)',
            border: 'rgba(56,189,248,0.15)',
            text: '#dde6f0',
            textDim: '#8898a8',
            textMuted: '#4a5c6e',
            accent: '#38bdf8',
            up: '#00e676',
            down: '#ff3d5a',
            fx: '#a78bfa',
            cardShadow: '0 8px 32px rgba(0,0,0,0.4)',
        },
        light: {
            bg: 'linear-gradient(145deg, #f0f4f8 0%, #e8eef5 50%, #f0f4f8 100%)',
            cardBg: 'rgba(255,255,255,0.9)',
            border: 'rgba(0,119,204,0.2)',
            text: '#1a2535',
            textDim: '#4a5c72',
            textMuted: '#8a9ab0',
            accent: '#0077cc',
            up: '#00b850',
            down: '#e01840',
            fx: '#7c5cbf',
            cardShadow: '0 8px 32px rgba(0,0,0,0.1)',
        },
        purple: {
            bg: 'linear-gradient(145deg, #0a0514 0%, #1a0d2e 50%, #0a0514 100%)',
            cardBg: 'rgba(30,15,60,0.9)',
            border: 'rgba(167,139,250,0.2)',
            text: '#ede9fe',
            textDim: '#c4b5fd',
            textMuted: '#8b5cf6',
            accent: '#a78bfa',
            up: '#34d399',
            down: '#f87171',
            fx: '#fbbf24',
            cardShadow: '0 8px 32px rgba(0,0,0,0.5)',
        },
        green: {
            bg: 'linear-gradient(145deg, #030d07 0%, #0d2218 50%, #030d07 100%)',
            cardBg: 'rgba(13,34,24,0.9)',
            border: 'rgba(52,211,153,0.2)',
            text: '#d1fae5',
            textDim: '#6ee7b7',
            textMuted: '#34d399',
            accent: '#34d399',
            up: '#22c55e',
            down: '#f87171',
            fx: '#a3e635',
            cardShadow: '0 8px 32px rgba(0,0,0,0.4)',
        },
    };
    var T = tokens[style] || tokens.dark;

    var btc = data && data.btc;
    var box = data && data.box;
    var fx = data && data.fx || {};
    var stocks = data && data.stocks && data.stocks.all || {};

    var rows = Object.entries(stocks)
        .filter(function(e) { return e[1] && typeof e[1].pct === 'number'; })
        .map(function(e) { return { ticker: e[0], d: e[1] }; });
    rows.sort(function(a,b){ return b.d.pct - a.d.pct; });
    var best = rows[0];
    var worst = rows[rows.length - 1];

    var updatedAt = data && data.updated_at
        ? data.updated_at.split(' ').slice(1).join(' ')
        : new Date().toTimeString().split(' ')[0];

    function metricCard(label, value, cls) {
        var c = T[cls] || T.textDim;
        return '<div style="background:' + T.cardBg + ';border:1px solid ' + T.border + ';' +
            'border-radius:10px;padding:12px 14px;flex:1;min-width:90px;box-shadow:' + T.cardShadow + ';">' +
            '<div style="font-size:0.6rem;color:' + T.textMuted + ';text-transform:uppercase;' +
            'letter-spacing:0.08em;margin-bottom:4px;">' + _esc(label) + '</div>' +
            '<div style="font-size:1.05rem;font-weight:700;font-family:\'IBM Plex Mono\',monospace;' +
            'color:' + c + ';letter-spacing:-0.03em;">' + _esc(value) + '</div></div>';
    }

    function tickerRow(ticker, d) {
        if (!d || !d.ok) return '';
        var pct = _trendSign(d.pct, true);
        var cls = _trendClass(d.pct) === 'up' ? T.up : (_trendClass(d.pct) === 'down' ? T.down : T.textDim);
        return '<div style="display:flex;justify-content:space-between;align-items:center;' +
            'padding:5px 0;border-bottom:1px solid ' + T.border + ';">' +
            '<span style="font-size:0.8rem;font-weight:600;color:' + T.accent + ';' +
            'font-family:\'IBM Plex Mono\',monospace;">' + _esc(ticker) + '</span>' +
            '<span style="font-size:0.78rem;color:' + T.textDim + ';">' + _esc(d.name || '') + '</span>' +
            '<span style="font-size:0.8rem;font-weight:600;font-family:\'IBM Plex Mono\',monospace;' +
            'color:' + cls + ';">' + pct + '</span></div>';
    }

    var btcPrice = btc != null ? '$' + _fmt(btc, 2) : '--';
    var boxPrice = box != null ? '$' + _fmt(box, 4) : '--';
    var usdCny = fx && fx.USD_CNY && fx.USD_CNY.rate != null ? _fmt(fx.USD_CNY.rate, 4) : '--';
    var usdHkd = fx && fx.USD_HKD && fx.USD_HKD.rate != null ? _fmt(fx.USD_HKD.rate, 4) : '--';
    var hkdCny = fx && fx.HKD_CNY && fx.HKD_CNY.rate != null ? _fmt(fx.HKD_CNY.rate, 4) : '--';
    var bestStr = best ? best.ticker + ' ' + _trendSign(best.d.pct, true) : '--';
    var worstStr = worst ? worst.ticker + ' ' + _trendSign(worst.d.pct, true) : '--';

    var html = '<div id="__share_card__" style="width:440px;padding:0;' +
        'font-family:\'Noto Sans SC\',\'PingFang SC\',sans-serif;' +
        'background:' + T.bg + ';color:' + T.text + ';user-select:none;' +
        'position:relative;overflow:hidden;">';

    html += '<div style="position:absolute;top:-40px;left:50%;transform:translateX(-50%);' +
        'width:300px;height:80px;background:radial-gradient(ellipse, ' + T.accent + '22 0%, transparent 70%);' +
        'pointer-events:none;"></div>';

    html += '<div style="padding:20px 20px 12px;position:relative;">' +
        '<div style="font-size:0.62rem;color:' + T.textMuted + ';text-transform:uppercase;' +
        'letter-spacing:0.12em;margin-bottom:6px;">' + _esc(updatedAt) + '</div>' +
        '<div style="font-size:1.25rem;font-weight:700;color:' + T.text + ';letter-spacing:-0.02em;">' +
        _esc(title) + '</div>';
    if (sub) {
        html += '<div style="font-size:0.7rem;color:' + T.textDim + ';margin-top:2px;">' + _esc(sub) + '</div>';
    }
    html += '</div>';

    html += '<div style="display:flex;gap:8px;padding:0 20px 14px;flex-wrap:wrap;">' +
        metricCard('BTC/USD', btcPrice, 'up') +
        metricCard('BOX/USD', boxPrice, 'up') +
        metricCard('USD/CNY', usdCny, 'fx') + '</div>';

    html += '<div style="display:flex;gap:8px;padding:0 20px 14px;">' +
        metricCard('USD/HKD', usdHkd, 'fx') +
        metricCard('HKD/CNY', hkdCny, 'fx') +
        metricCard('最强', bestStr, 'up') +
        metricCard('最弱', worstStr, 'down') + '</div>';

    var topTickers = rows.slice(0, 6);
    if (topTickers.length > 0) {
        html += '<div style="margin:0 20px 14px;background:' + T.cardBg + ';border:1px solid ' + T.border + ';' +
            'border-radius:10px;padding:10px 12px;box-shadow:' + T.cardShadow + ';">' +
            '<div style="font-size:0.62rem;color:' + T.textMuted + ';text-transform:uppercase;' +
            'letter-spacing:0.08em;margin-bottom:6px;">行情一览</div>' +
            topTickers.map(function(r){ return tickerRow(r.ticker, r.d); }).join('') + '</div>';
    }

    html += '<div style="display:flex;align-items:center;justify-content:space-between;' +
        'padding:12px 20px 18px;">' +
        '<div style="display:flex;align-items:center;gap:10px;">' +
        '<div id="__share_qr__" style="width:64px;height:64px;background:#fff;' +
        'border-radius:8px;padding:4px;flex-shrink:0;"></div>' +
        '<div>' +
        '<div style="font-size:0.68rem;color:' + T.textDim + ';line-height:1.5;">扫码查看完整数据</div>' +
        '<div style="font-size:0.6rem;color:' + T.textMuted + ';margin-top:2px;">一轩资产控制台 · 实时行情</div>' +
        '</div></div>' +
        '<div style="text-align:right;">' +
        '<div style="font-size:0.6rem;color:' + T.accent + ';opacity:0.6;">v2</div>' +
        '</div></div>';

    html += '</div>';
    return html;
}

function _getShareOpts() {
    return {
        title: $('#share-title-input').val().trim() ||
            ('一轩资产日报 · ' + new Date().toLocaleDateString('zh-CN').replace(/\//g, '.')),
        sub: $('#share-sub-input').val().trim(),
        qrUrl: $('#share-url-input').val().trim(),
        style: _shareStyle,
    };
}

function _renderShareCard(opts, onCanvasReady) {
    $.get('/api/finance/data', function(data) {
        var html = _buildShareCard(data, opts);
        $('#share-preview-canvas').hide();
        $('#share-preview-loading').show().html(
            '<div class="share-loading-spinner"></div>正在渲染预览…'
        );

        $('#share-card-preview').html(html);

        var qrEl = document.getElementById('__share_qr__');
        var qrUrl = opts.qrUrl || window.location.href;
        new QRCode(qrEl, {
            text: qrUrl,
            width: 56,
            height: 56,
            colorDark: '#000000',
            colorLight: '#ffffff',
            correctLevel: QRCode.CorrectLevel.L,
        });

        setTimeout(function() {
            var cardEl = document.getElementById('__share_card__');
            if (!cardEl) return;
            html2canvas(cardEl, {
                scale: 2,
                useCORS: true,
                backgroundColor: null,
                logging: false,
            }).then(function(canvas) {
                var $canvas = $(canvas);
                $canvas.css({ width: '100%', display: 'block', 'border-radius': '0' });
                $('#share-card-preview').html($canvas);
                $('#share-preview-loading').hide();
                _previewRendered = true;
                if (onCanvasReady) onCanvasReady(canvas);
            }).catch(function(e) {
                $('#share-preview-loading').html('⚠️ 渲染失败，请重试');
                console.error('html2canvas error:', e);
            });
        }, 120);
    }).fail(function() {
        $('#share-preview-loading').html('⚠️ 数据获取失败，请重试');
    });
}

function initShareCard($) {
    // Open modal
    $('#share-btn').on('click', function() {
        _shareStyle = 'dark';
        $('.share-style-option').removeClass('active').filter('[data-style=dark]').addClass('active');
        $('#share-title-input').val(
            '一轩资产日报 · ' + new Date().toLocaleDateString('zh-CN').replace(/\//g, '.')
        );
        $('#share-sub-input').val('一轩资产控制台 · 实时行情');
        $('#share-url-input').val(window.location.href);
        _previewRendered = false;
        $('#share-card-preview').html(
            '<div class="share-loading" id="share-preview-loading">' +
            '<div class="share-loading-spinner"></div>正在渲染预览…</div>' +
            '<canvas id="share-preview-canvas" style="display:none"></canvas>'
        );
        $('#share-modal').addClass('active');
        document.body.style.overflow = 'hidden';
        _renderShareCard(_getShareOpts());
    });

    // Close modal
    $('#share-modal-close').on('click', function() {
        $('#share-modal').removeClass('active');
        document.body.style.overflow = '';
    });
    $('#share-modal').on('click', function(e) {
        if (e.target === this) {
            $(this).removeClass('active');
            document.body.style.overflow = '';
        }
    });

    // Style toggle
    $('.share-style-option').on('click', function() {
        $('.share-style-option').removeClass('active');
        $(this).addClass('active');
        _shareStyle = $(this).data('style');
        _refreshPreview();
    });

    // Auto-refresh on input blur (no need to manually click refresh)
    $('#share-title-input, #share-sub-input, #share-url-input').on('blur', function() {
        _refreshPreview();
    });

    // Refresh preview (manual trigger still works)
    $('#share-refresh-btn').on('click', _refreshPreview);

    function _refreshPreview() {
        _previewRendered = false;
        $('#share-card-preview').html(
            '<div class="share-loading" id="share-preview-loading">' +
            '<div class="share-loading-spinner"></div>正在渲染预览…</div>' +
            '<canvas id="share-preview-canvas" style="display:none"></canvas>'
        );
        _renderShareCard(_getShareOpts());
    }

    // Download PNG
    $('#share-download-btn').on('click', function() {
        var $btn = $(this);
        if (!_previewRendered) {
            $btn.text('🔄 先生成预览…');
            setTimeout(function() { $btn.text('📥 下载 PNG'); }, 1500);
            return;
        }
        $btn.prop('disabled', true).text('⏳ 生成中…');
        _renderShareCard(_getShareOpts(), function(canvas) {
            var link = document.createElement('a');
            var dateStr = new Date().toISOString().slice(0, 10);
            link.download = '一轩资产日报_' + dateStr + '.png';
            link.href = canvas.toDataURL('image/png');
            link.click();
            $btn.prop('disabled', false).text('📥 下载 PNG');
        });
    });
}

// Auto-initialize — called explicitly by layui.use callback in finance.html