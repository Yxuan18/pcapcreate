// 壁纸网站 URL（需要实际的 API 或图片地址）
const wallpaperURL = 'https://www.bing.com/th?id=OHR.PointReyes_EN-US4731803211_1920x1080.jpg';

// 本地默认背景图片 URL
const fallbackWallpaper = "/static/default_background.jpg";  // 使用相对路径

// 尝试从壁纸网站加载背景
fetch(wallpaperURL)
    .then(response => {
        if (response.ok) {
            document.body.style.backgroundImage = `url(${wallpaperURL})`;
        } else {
            // 如果获取失败，使用本地默认背景
            document.body.style.backgroundImage = `url(${fallbackWallpaper})`;
        }
    })
    .catch(() => {
        // 网络错误时使用本地默认背景
        document.body.style.backgroundImage = `url(${fallbackWallpaper})`;
    });