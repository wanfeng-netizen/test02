export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;
    const path = decodeURIComponent(url.pathname.slice(1));
    
    // 1. 认证检查
    const auth = await authenticate(request, env);
    if (!auth.authenticated) {
      return new Response('Unauthorized', {
        status: 401,
        headers: {
          'WWW-Authenticate': 'Basic realm="R2 WebDAV"',
          'Content-Type': 'text/plain'
        }
      });
    }
    
    // 2. CORS 预检请求
    if (method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'DAV': '1,2',
          'Allow': 'GET,PUT,DELETE,PROPFIND,MKCOL,OPTIONS',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,PUT,DELETE,PROPFIND,MKCOL,OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Allow-Credentials': 'true',
          'Access-Control-Max-Age': '86400'
        }
      });
    }
    
    // 3. 路由处理
    try {
      switch(method) {
        case 'GET':
        case 'HEAD':
          return await handleGet(path, request, env);
        case 'PUT':
          return await handlePut(path, request, env);
        case 'DELETE':
          return await handleDelete(path, env);
        case 'PROPFIND':
          return await handlePropFind(path, request, env);
        case 'MKCOL':
          return await handleMkcol(path, env);
        default:
          return new Response(`Method ${method} not allowed`, {
            status: 405,
            headers: { 'Allow': 'GET,PUT,DELETE,PROPFIND,MKCOL,OPTIONS' }
          });
      }
    } catch (error) {
      console.error('WebDAV error:', error);
      return new Response(`Internal Server Error: ${error.message}`, {
        status: 500,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
  }
};

// 认证函数
async function authenticate(request, env) {
  // 如果未设置用户名密码，跳过认证
  if (!env.WEBDAV_USERNAME || !env.WEBDAV_PASSWORD) {
    return { authenticated: true, username: 'anonymous' };
  }
  
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return { authenticated: false };
  }
  
  const base64Credentials = authHeader.slice(6);
  const credentials = atob(base64Credentials);
  const [username, password] = credentials.split(':');
  
  if (username === env.WEBDAV_USERNAME && password === env.WEBDAV_PASSWORD) {
    return { authenticated: true, username };
  }
  
  return { authenticated: false };
}

// GET 请求 - 下载文件
async function handleGet(path, request, env) {
  const object = await env.R2_BUCKET.get(path);
  
  if (!object) {
    // 检查是否是目录（以 / 结尾）
    if (!path.endsWith('/')) {
      const list = await env.R2_BUCKET.list({ prefix: path + '/' });
      if (list.objects.length > 0) {
        // 这是一个目录，返回目录列表
        return generateDirectoryListing(path, list, env);
      }
    }
    return new Response('Not Found', { status: 404 });
  }
  
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set('etag', object.httpEtag);
  headers.set('Content-Length', object.size);
  headers.set('Accept-Ranges', 'bytes');
  
  // 处理 Range 请求（断点续传）
  const range = request.headers.get('range');
  if (range) {
    const [start, end] = parseRange(range, object.size);
    headers.set('Content-Range', `bytes ${start}-${end}/${object.size}`);
    headers.set('Content-Length', end - start + 1);
    
    const body = await object.arrayBuffer();
    return new Response(body.slice(start, end + 1), {
      status: 206,
      headers
    });
  }
  
  return new Response(object.body, { headers });
}

// PUT 请求 - 上传文件
async function handlePut(path, request, env) {
  const contentLength = request.headers.get('content-length');
  
  // 检查文件大小（限制为 100MB，Worker 限制）
  if (contentLength > 100 * 1024 * 1024) {
    return new Response('File too large. Max 100MB', { status: 413 });
  }
  
  try {
    await env.R2_BUCKET.put(path, request.body, {
      httpMetadata: request.headers
    });
    
    return new Response('Created', {
      status: 201,
      headers: {
        'Content-Type': 'text/plain',
        'Location': `/${path}`
      }
    });
  } catch (error) {
    return new Response(`Upload failed: ${error.message}`, { status: 500 });
  }
}

// DELETE 请求 - 删除文件
async function handleDelete(path, env) {
  const object = await env.R2_BUCKET.get(path);
  
  if (!object) {
    // 尝试删除目录（删除所有以该路径开头的对象）
    const list = await env.R2_BUCKET.list({ prefix: path.endsWith('/') ? path : path + '/' });
    
    if (list.objects.length > 0) {
      // 批量删除目录下的所有文件
      for (const obj of list.objects) {
        await env.R2_BUCKET.delete(obj.key);
      }
      return new Response('OK', { status: 200 });
    }
    
    return new Response('Not Found', { status: 404 });
  }
  
  await env.R2_BUCKET.delete(path);
  return new Response('No Content', { status: 204 });
}

// PROPFIND 请求 - 列出目录内容（iPhone 文件浏览需要这个）
async function handlePropFind(path, request, env) {
  const depth = request.headers.get('Depth') || '1';
  const requestedPath = path === '' ? '' : (path.endsWith('/') ? path : path + '/');
  
  // 获取文件列表
  const list = await env.R2_BUCKET.list({
    prefix: requestedPath,
    delimiter: '/'
  });
  
  // 构建 WebDAV XML 响应
  let xml = `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">`;
  
  // 添加当前目录本身
  const currentPath = path === '' ? '/' : `/${path}`;
  xml += `
  <D:response>
    <D:href>${currentPath}</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>${path === '' ? 'Root' : path.split('/').pop()}</D:displayname>
        <D:creationdate>${new Date().toISOString()}</D:creationdate>
        <D:getlastmodified>${new Date().toUTCString()}</D:lastmodified>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`;
  
  // 添加目录内容
  for (const obj of list.objects) {
    const relativePath = obj.key.slice(requestedPath.length);
    if (relativePath === '') continue; // 跳过自身
    
    const isDirectory = obj.key.endsWith('/');
    const fullPath = `/${obj.key}`;
    const displayName = isDirectory ? relativePath.slice(0, -1) : relativePath;
    
    xml += `
  <D:response>
    <D:href>${fullPath}</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype>${isDirectory ? '<D:collection/>' : ''}</D:resourcetype>
        <D:displayname>${displayName}</D:displayname>
        <D:getcontentlength>${isDirectory ? '0' : obj.size}</D:getcontentlength>
        <D:creationdate>${obj.uploaded.toISOString()}</D:creationdate>
        <D:getlastmodified>${obj.uploaded.toUTCString()}</D:lastmodified>
        <D:getcontenttype>${isDirectory ? 'httpd/unix-directory' : getContentType(obj.key)}</D:getcontenttype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`;
  }
  
  // 添加子目录（如果有）
  for (const dir of list.delimitedPrefixes || []) {
    const dirName = dir.slice(requestedPath.length, -1);
    xml += `
  <D:response>
    <D:href>/${requestedPath}${dirName}/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:displayname>${dirName}</D:displayname>
        <D:creationdate>${new Date().toISOString()}</D:creationdate>
        <D:getlastmodified>${new Date().toUTCString()}</D:lastmodified>
        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`;
  }
  
  xml += '\n</D:multistatus>';
  
  return new Response(xml, {
    status: 207,
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'DAV': '1,2',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

// MKCOL 请求 - 创建目录
async function handleMkcol(path, env) {
  if (!path.endsWith('/')) {
    path = path + '/';
  }
  
  // 检查是否已存在
  const existing = await env.R2_BUCKET.get(path);
  if (existing) {
    return new Response('Method Not Allowed', { status: 405 });
  }
  
  // 在 R2 中创建目录实际上是创建一个空对象
  await env.R2_BUCKET.put(path, new Uint8Array(0), {
    httpMetadata: {
      contentType: 'httpd/unix-directory'
    }
  });
  
  return new Response('Created', { status: 201 });
}

// 辅助函数：生成目录列表 HTML（浏览器访问时用）
async function generateDirectoryListing(path, list, env) {
  const title = path === '' ? 'Root Directory' : `Directory: ${path}`;
  
  let html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${title}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; }
    h1 { color: #333; }
    ul { list-style: none; padding: 0; }
    li { padding: 8px; border-bottom: 1px solid #eee; }
    a { text-decoration: none; color: #0066cc; }
    a:hover { text-decoration: underline; }
    .size { color: #666; font-size: 0.9em; }
    .directory:before { content: "📁 "; }
    .file:before { content: "📄 "; }
  </style>
</head>
<body>
  <h1>${title}</h1>
  <ul>`;
  
  // 添加父目录链接
  if (path !== '') {
    const parent = path.split('/').slice(0, -1).join('/');
    html += `<li class="directory"><a href="${parent ? '/' + parent : '/'}">.. (Parent Directory)</a></li>`;
  }
  
  // 添加子目录
  for (const dir of list.delimitedPrefixes || []) {
    const dirName = dir.slice(path.length, -1);
    html += `<li class="directory"><a href="/${dir}">${dirName}/</a></li>`;
  }
  
  // 添加文件
  for (const obj of list.objects) {
    const fileName = obj.key.slice(path.length);
    const size = formatFileSize(obj.size);
    html += `<li class="file">
      <a href="/${obj.key}">${fileName}</a>
      <span class="size">(${size})</span>
    </li>`;
  }
  
  html += `</ul>
  <p><small>Powered by Cloudflare Worker WebDAV</small></p>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache'
    }
  });
}

// 辅助函数：解析 Range 头
function parseRange(range, size) {
  const matches = range.match(/bytes=(\d+)-(\d*)/);
  if (!matches) return [0, size - 1];
  
  let start = parseInt(matches[1], 10);
  let end = matches[2] ? parseInt(matches[2], 10) : size - 1;
  
  if (start >= size) return [0, size - 1];
  if (end >= size) end = size - 1;
  
  return [start, end];
}

// 辅助函数：获取文件类型
function getContentType(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const types = {
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'webp': 'image/webp',
    'pdf': 'application/pdf',
    'txt': 'text/plain',
    'html': 'text/html',
    'css': 'text/css',
    'js': 'application/javascript',
    'json': 'application/json',
    'mp4': 'video/mp4',
    'mp3': 'audio/mpeg',
    'mov': 'video/quicktime',
    'zip': 'application/zip'
  };
  return types[ext] || 'application/octet-stream';
}

// 辅助函数：格式化文件大小
function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
