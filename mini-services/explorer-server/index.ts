import { readdir, stat, readFile } from "fs/promises";
import { join, extname, resolve } from "path";
import { createServer } from "http";

const PORT = 3000;
const ROOT = "/home/z/my-project";
const SKIP = new Set(["node_modules", ".git", ".next", "__pycache__", ".cache", ".zig-cache", "zig-out", "mini-services"]);

interface FInfo {
  name: string;
  path: string;
  size: number;
  isDir: boolean;
  ext: string;
}

function fmtSize(b: number): string {
  if (b === 0) return "0 B";
  const k = 1024;
  const s = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return parseFloat((b / Math.pow(k, i)).toFixed(1)) + " " + s[i];
}

async function listDir(dirPath: string): Promise<{ files: FInfo[]; currentPath: string; parentPath: string | null }> {
  const resolved = resolve(dirPath);
  if (!resolved.startsWith(ROOT)) throw new Error("Access denied");
  const entries = await readdir(resolved, { withFileTypes: true });
  const files: FInfo[] = [];
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".gitignore") continue;
    if (e.isDirectory() && SKIP.has(e.name)) continue;
    const full = join(resolved, e.name);
    try {
      const s = await stat(full);
      files.push({ name: e.name, path: full, size: s.size, isDir: e.isDirectory(), ext: extname(e.name).toLowerCase() });
    } catch { continue; }
  }
  files.sort((a, b) => { if (a.isDir !== b.isDir) return a.isDir ? -1 : 1; return a.name.localeCompare(b.name); });
  let parentPath: string | null = null;
  if (resolved !== ROOT) { const p = resolve(resolved, ".."); if (p.startsWith(ROOT)) parentPath = p; }
  return { files, currentPath: resolved, parentPath };
}

const TEXT_EXTS = new Set([".md",".txt",".json",".csv",".js",".ts",".tsx",".py",".zig",".html",".css",".xml",".yaml",".yml",".toml",".sh",".log",".rs",".go",".c",".h",".cpp",".s",".ld",".cfg",".gitignore",".mjs",".prisma"]);

async function readText(filePath: string): Promise<string | null> {
  const resolved = resolve(filePath);
  if (!resolved.startsWith(ROOT)) return null;
  const ext = extname(filePath).toLowerCase();
  if (!TEXT_EXTS.has(ext)) return null;
  try {
    const s = await stat(filePath);
    if (s.isDirectory() || s.size > 2 * 1024 * 1024) return null;
    return await readFile(filePath, "utf-8");
  } catch { return null; }
}

const MIME: Record<string, string> = {
  ".pdf":"application/pdf",".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".gif":"image/gif",".svg":"image/svg+xml",
  ".md":"text/markdown",".txt":"text/plain",".json":"application/json",".csv":"text/csv",".html":"text/html",".css":"text/css",
  ".js":"text/javascript",".ts":"text/typescript",".tsx":"text/typescript",".py":"text/x-python",".zig":"text/plain",".sh":"text/x-shellscript",
};

function renderPage(files: FInfo[], currentPath: string, parentPath: string | null, search: string): string {
  const root = ROOT;
  const rel = currentPath.startsWith(root) ? currentPath.slice(root.length) : currentPath;
  const parts = rel.split("/").filter(Boolean);
  const crumbs: { label: string; path: string }[] = [{ label: "~", path: root }];
  let cur = root;
  for (const p of parts) { cur += "/" + p; crumbs.push({ label: p, path: cur }); }

  const dirCount = files.filter(f => f.isDir).length;
  const fileCount = files.filter(f => !f.isDir).length;

  const filtered = search.trim()
    ? files.filter(f => f.name.toLowerCase().includes(search.toLowerCase()))
    : files;

  const breadcrumbHtml = crumbs.map((c, i) =>
    `${i > 0 ? '<span style="color:#334155">/</span>' : ''}<a href="/?dir=${encodeURIComponent(c.path)}" style="color:${i === crumbs.length - 1 ? '#cbd5e1' : '#64748b'};text-decoration:none;font-size:12px">${c.label}</a>`
  ).join(" ");

  const fileCards = filtered.map(f => {
    const emoji = f.isDir ? "📁" : f.ext === ".pdf" ? "📄" : f.ext === ".md" ? "📝" : [".png",".jpg",".gif",".svg"].includes(f.ext) ? "🖼️" : [".zig",".ts",".js",".py"].includes(f.ext) ? "💻" : "📃";
    const bg = f.isDir ? "rgba(245,158,11,0.1)" : f.ext === ".pdf" ? "rgba(239,68,68,0.1)" : "rgba(255,255,255,0.04)";
    if (f.isDir) {
      return `<a href="/?dir=${encodeURIComponent(f.path)}" style="display:flex;flex-direction:column;align-items:center;gap:6px;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,0.04);background:rgba(255,255,255,0.02);cursor:pointer;color:#fff;text-align:center;text-decoration:none;transition:background 0.15s" onmouseover="this.style.background='rgba(255,255,255,0.04)'" onmouseout="this.style.background='rgba(255,255,255,0.02)'">
        <div style="width:40px;height:40px;border-radius:8px;display:flex;align-items:center;justify-content:center;background:${bg};font-size:20px">${emoji}</div>
        <div style="font-size:11px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;width:100%">${f.name}</div>
        <div style="font-size:9px;color:#475569">Папка</div>
      </a>`;
    }
    return `<div class="file-card" data-path="${f.path}" data-ext="${f.ext}" data-name="${f.name}" data-size="${f.size}" style="display:flex;flex-direction:column;align-items:center;gap:6px;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,0.04);background:rgba(255,255,255,0.02);cursor:pointer;color:#fff;text-align:center;transition:background 0.15s" onmouseover="this.style.background='rgba(255,255,255,0.04)'" onmouseout="this.style.background='rgba(255,255,255,0.02)'">
      <div style="width:40px;height:40px;border-radius:8px;display:flex;align-items:center;justify-content:center;background:${bg};font-size:20px">${emoji}</div>
      <div style="font-size:11px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;width:100%">${f.name}</div>
      <div style="font-size:9px;color:#475569">${fmtSize(f.size)}</div>
    </div>`;
  }).join("");

  return `<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>POLER-OS Проводник</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0a12;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;height:100vh;overflow:hidden}
.app{display:flex;flex-direction:column;height:100vh}
header{flex-shrink:0;border-bottom:1px solid rgba(255,255,255,0.06);background:rgba(14,14,24,0.8);padding:8px 16px}
.hdr-row{display:flex;align-items:center;gap:12px}
.nav-btn{background:none;border:none;color:#94a3b8;cursor:pointer;padding:4px 8px;border-radius:4px;font-size:14px}
.nav-btn:hover{background:rgba(255,255,255,0.06);color:#fff}
.search-box{flex:1;max-width:480px;position:relative}
.search-box input{width:100%;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:6px 12px;color:#fff;font-size:14px;outline:none}
.search-box input:focus{border-color:rgba(6,182,212,0.4)}
.breadcrumbs{display:flex;align-items:center;gap:4px;margin-top:4px;font-size:12px}
.content{display:flex;flex:1;overflow:hidden}
.file-grid{flex:1;overflow-y:auto;padding:12px;display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px}
.file-card.selected{background:rgba(6,182,212,0.08)!important;border-color:rgba(6,182,212,0.3)!important}
.preview{width:420px;flex-shrink:0;border-left:1px solid rgba(255,255,255,0.06);background:#0c0c16;display:flex;flex-direction:column;overflow:hidden}
.preview-hdr{display:flex;align-items:center;justify-content:space-between;padding:8px 16px;border-bottom:1px solid rgba(255,255,255,0.06);font-size:14px;font-weight:500}
.preview-meta{padding:8px 16px;border-bottom:1px solid rgba(255,255,255,0.06);font-size:12px;color:#64748b}
.preview-body{flex:1;overflow:auto;padding:16px}
.close-btn{background:none;border:none;color:#666;cursor:pointer;font-size:16px}
.close-btn:hover{color:#fff}
pre.code{font-size:12px;color:#cbd5e1;white-space:pre-wrap;word-break:break-all;background:rgba(255,255,255,0.02);padding:12px;border-radius:8px;border:1px solid rgba(255,255,255,0.05);max-height:calc(100vh - 220px);overflow:auto;font-family:'Fira Code',monospace,monospace}
.stats{color:#334155;margin-left:8px;font-size:12px}
.empty{display:flex;align-items:center;justify-content:center;height:100%;color:#475569;font-size:14px}
.dl-btn{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:8px;background:rgba(6,182,212,0.1);color:#22d3ee;font-size:12px;text-decoration:none;margin-top:8px}
.dl-btn:hover{background:rgba(6,182,212,0.2)}
</style></head>
<body>
<div class="app">
<header>
  <div class="hdr-row">
    <div style="display:flex;gap:4px">
      ${parentPath ? `<a href="/?dir=${encodeURIComponent(parentPath)}" class="nav-btn">← Назад</a>` : '<button class="nav-btn" disabled>← Назад</button>'}
      <a href="/?dir=${encodeURIComponent(root)}" class="nav-btn">🏠 Домой</a>
      <a href="/?dir=${encodeURIComponent(currentPath)}" class="nav-btn">🔄</a>
    </div>
    <div class="search-box">
      <input type="text" placeholder="Поиск файлов..." id="search" value="${search.replace(/"/g, '&quot;')}" />
    </div>
  </div>
  <div class="breadcrumbs">
    ${breadcrumbHtml}
    <span class="stats">${dirCount} папок, ${fileCount} файлов</span>
  </div>
</header>
<div class="content">
  <div class="file-grid" id="fileGrid">
    ${fileCards || '<div class="empty">Папка пуста</div>'}
  </div>
  <div class="preview" id="previewPanel" style="display:none">
    <div class="preview-hdr"><span id="previewName"></span><button class="close-btn" id="closePreview">✕</button></div>
    <div class="preview-meta" id="previewMeta"></div>
    <div class="preview-body" id="previewBody"></div>
  </div>
</div>
</div>
<script>
const fileCards = document.querySelectorAll('.file-card');
const previewPanel = document.getElementById('previewPanel');
const previewName = document.getElementById('previewName');
const previewMeta = document.getElementById('previewMeta');
const previewBody = document.getElementById('previewBody');
const closePreview = document.getElementById('closePreview');
const searchInput = document.getElementById('search');

let searchTimeout;
searchInput.addEventListener('input', () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    const q = searchInput.value.toLowerCase();
    fileCards.forEach(c => {
      const name = c.dataset.name.toLowerCase();
      c.style.display = name.includes(q) ? '' : 'none';
    });
  }, 200);
});

fileCards.forEach(card => {
  card.addEventListener('click', async () => {
    fileCards.forEach(c => c.classList.remove('selected'));
    card.classList.add('selected');
    const path = card.dataset.path;
    const name = card.dataset.name;
    const size = parseInt(card.dataset.size);
    const ext = card.dataset.ext;
    previewName.textContent = name;
    previewMeta.textContent = formatSize(size) + ' · ' + path;
    previewPanel.style.display = 'flex';
    previewBody.innerHTML = '<div style="text-align:center;padding:32px;color:#475569">Загрузка...</div>';

    const textExts = [".md",".txt",".json",".js",".ts",".tsx",".py",".zig",".html",".css",".sh",".cfg",".ld",".s",".csv"];
    if (ext === ".pdf") {
      const furl = '/api/file?path='+encodeURIComponent(path);
      previewBody.innerHTML = '<iframe src="'+furl+'" style="width:100%;height:calc(100vh - 200px);min-height:400px;border:none;border-radius:8px;background:#fff" title="'+name+'"></iframe><a href="'+furl+'" download="'+name+'" class="dl-btn">⬇ Скачать PDF</a>';
    } else if (textExts.includes(ext)) {
      try {
        const res = await fetch('/api/text?path=' + encodeURIComponent(path));
        if (res.ok) {
          const data = await res.json();
          previewBody.innerHTML = '<pre class="code">'+escapeHtml(data.content.slice(0,50000))+(data.content.length>50000?'\\n...':'')+'</pre><a href="/api/file?path='+encodeURIComponent(path)+'" download="'+name+'" class="dl-btn">⬇ Скачать</a>';
        } else {
          previewBody.innerHTML = '<div style="color:#475569;text-align:center;padding:32px">Не удалось прочитать файл</div>';
        }
      } catch { previewBody.innerHTML = '<div style="color:#475569">Ошибка</div>'; }
    } else if ([".png",".jpg",".jpeg",".gif",".svg"].includes(ext)) {
      previewBody.innerHTML = '<img src="/api/file?path='+encodeURIComponent(path)+'" style="max-width:100%;border-radius:8px" alt="'+name+'" /><a href="/api/file?path='+encodeURIComponent(path)+'" download="'+name+'" class="dl-btn">⬇ Скачать</a>';
    } else {
      previewBody.innerHTML = '<div style="text-align:center;padding:32px;color:#475569">Предпросмотр недоступен</div><a href="/api/file?path='+encodeURIComponent(path)+'" download="'+name+'" class="dl-btn">⬇ Скачать</a>';
    }
  });
});

closePreview.addEventListener('click', () => {
  previewPanel.style.display = 'none';
  fileCards.forEach(c => c.classList.remove('selected'));
});

function formatSize(b) {
  if (b===0) return '0 B';
  const k=1024,s=['B','KB','MB','GB'];
  const i=Math.floor(Math.log(b)/Math.log(k));
  return parseFloat((b/Math.pow(k,i)).toFixed(1))+' '+s[i];
}

function escapeHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</body></html>`;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://localhost:${PORT}`);

  try {
    // API: list directory
    if (url.pathname === "/api/list") {
      const dir = url.searchParams.get("dir") || ROOT;
      const result = await listDir(dir);
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify(result));
    }

    // API: read text file
    if (url.pathname === "/api/text") {
      const filePath = url.searchParams.get("path");
      if (!filePath) { res.writeHead(400); return res.end("Missing path"); }
      const content = await readText(filePath);
      if (content === null) { res.writeHead(400); return res.end("Cannot read"); }
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ content }));
    }

    // API: serve file
    if (url.pathname === "/api/file") {
      const filePath = url.searchParams.get("path");
      if (!filePath) { res.writeHead(400); return res.end("Missing path"); }
      const resolved = resolve(filePath);
      if (!resolved.startsWith(ROOT)) { res.writeHead(403); return res.end("Access denied"); }
      try {
        const s = await stat(resolved);
        if (s.isDirectory()) { res.writeHead(400); return res.end("Is directory"); }
        if (s.size > 50 * 1024 * 1024) { res.writeHead(413); return res.end("Too large"); }
        const data = await readFile(resolved);
        const ext = extname(resolved).toLowerCase();
        const mime = MIME[ext] || "application/octet-stream";
        const name = resolved.split("/").pop() || "file";
        res.writeHead(200, {
          "Content-Type": mime,
          "Content-Length": String(data.length),
          "Content-Disposition": `inline; filename="${name}"`,
          "Cache-Control": "public, max-age=60",
        });
        return res.end(data);
      } catch { res.writeHead(404); return res.end("Not found"); }
    }

    // Page: render explorer
    const dir = url.searchParams.get("dir") || ROOT;
    const search = url.searchParams.get("q") || "";
    const result = await listDir(dir);
    const html = renderPage(result.files, result.currentPath, result.parentPath, search);
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(html);
  } catch (err) {
    console.error(err);
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("Internal error: " + String(err));
  }
});

server.listen(PORT, () => {
  console.log(`Explorer server running on http://localhost:${PORT}`);
});
