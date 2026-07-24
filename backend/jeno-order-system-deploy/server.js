// ============================================
// JÉNO Pâtisserie & Café — Backend Server
// 使用 Node.js 內建的 http 模組,不依賴外部套件
// ============================================

const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";

const PRODUCTS_FILE = path.join(__dirname, "data", "products.json");
const ORDERS_FILE = path.join(__dirname, "data", "orders.json");
const PUBLIC_DIR = path.join(__dirname, "public");

// ---------- 小工具函式 ----------

// 讀取 JSON 檔案,回傳解析後的資料
function readJsonFile(filePath) {
  const raw = fs.readFileSync(filePath, "utf-8");
  return JSON.parse(raw);
}

// 把資料寫回 JSON 檔案(縮排 2 格,方便人眼閱讀)
function writeJsonFile(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
}

// 統一的 JSON 回應格式
function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*", // 開發階段先開放,正式上線建議改成指定網域
  });
  res.end(JSON.stringify(data));
}

// 讀取 POST 請求的內容(request body)
function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error("Request body is too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
  });
}

// 根據副檔名決定 Content-Type(讓瀏覽器知道這是 html/css/js/圖片...)
function getContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const types = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css",
    ".js": "application/javascript",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".svg": "image/svg+xml",
  };
  return types[ext] || "application/octet-stream";
}

// ---------- 主要的請求處理邏輯 ----------

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  try {
    // 部署平台可用此端點確認服務仍正常運作
    if (pathname === "/health" && req.method === "GET") {
      return sendJson(res, 200, { status: "ok" });
    }

    // --- API: 取得所有商品 ---
    if (pathname === "/api/products" && req.method === "GET") {
      const products = readJsonFile(PRODUCTS_FILE);
      return sendJson(res, 200, products);
    }

    // --- API: 新增商品 ---
    if (pathname === "/api/products" && req.method === "POST") {
      const body = await readRequestBody(req);

      if (!body.name || !body.category || body.price === undefined) {
        return sendJson(res, 400, { error: "name, category, and price are required." });
      }

      const products = readJsonFile(PRODUCTS_FILE);

      const newProduct = {
        id: "item_" + Date.now(), // 用時間戳記產生不會重複的商品編號
        category: body.category,
        name: body.name,
        price: Number(body.price),
        emoji: body.emoji || "🍽️",
      };

      products.push(newProduct);
      writeJsonFile(PRODUCTS_FILE, products);

      return sendJson(res, 201, { message: "Product added", product: newProduct });
    }

    // --- API: 編輯商品(網址例如 /api/products/item1) ---
    if (pathname.startsWith("/api/products/") && req.method === "PUT") {
      const id = pathname.split("/api/products/")[1];
      const body = await readRequestBody(req);

      const products = readJsonFile(PRODUCTS_FILE);
      const index = products.findIndex((p) => p.id === id);

      if (index === -1) {
        return sendJson(res, 404, { error: "Product not found." });
      }

      // 只更新有傳進來的欄位,其他欄位維持原值
      products[index] = {
        ...products[index],
        ...(body.name !== undefined && { name: body.name }),
        ...(body.category !== undefined && { category: body.category }),
        ...(body.price !== undefined && { price: Number(body.price) }),
        ...(body.emoji !== undefined && { emoji: body.emoji }),
      };

      writeJsonFile(PRODUCTS_FILE, products);

      return sendJson(res, 200, { message: "Product updated", product: products[index] });
    }

    // --- API: 刪除商品(網址例如 /api/products/item1) ---
    if (pathname.startsWith("/api/products/") && req.method === "DELETE") {
      const id = pathname.split("/api/products/")[1];

      const products = readJsonFile(PRODUCTS_FILE);
      const filtered = products.filter((p) => p.id !== id);

      if (filtered.length === products.length) {
        return sendJson(res, 404, { error: "Product not found." });
      }

      writeJsonFile(PRODUCTS_FILE, filtered);

      return sendJson(res, 200, { message: "Product deleted" });
    }

    // --- API: 建立新訂單 ---
    if (pathname === "/api/orders" && req.method === "POST") {
      const body = await readRequestBody(req);

      // 基本驗證:確認有帶商品清單,而且不是空的
      if (!body.items || Object.keys(body.items).length === 0) {
        return sendJson(res, 400, { error: "Order must contain at least one item." });
      }

      const orders = readJsonFile(ORDERS_FILE);

      const newOrder = {
        id: "order_" + Date.now(), // 用時間戳記當簡單的訂單編號
        items: body.items,
        total: body.total,
        createdAt: new Date().toISOString(),
        status: "received",
      };

      orders.push(newOrder);
      writeJsonFile(ORDERS_FILE, orders);

      return sendJson(res, 201, { message: "Order received", order: newOrder });
    }

    // --- API: 取得所有訂單(給店家後台看的) ---
    if (pathname === "/api/orders" && req.method === "GET") {
      const orders = readJsonFile(ORDERS_FILE);
      return sendJson(res, 200, orders);
    }

    // --- API: 更新訂單狀態 ---
    if (pathname.startsWith("/api/orders/") && req.method === "PATCH") {
      const id = decodeURIComponent(pathname.split("/api/orders/")[1]);
      const body = await readRequestBody(req);
      const allowedStatuses = ["received", "preparing", "ready", "completed", "cancelled"];

      if (!allowedStatuses.includes(body.status)) {
        return sendJson(res, 400, { error: "Invalid order status." });
      }

      const orders = readJsonFile(ORDERS_FILE);
      const order = orders.find((item) => item.id === id);

      if (!order) {
        return sendJson(res, 404, { error: "Order not found." });
      }

      order.status = body.status;
      writeJsonFile(ORDERS_FILE, orders);
      return sendJson(res, 200, { message: "Order updated", order });
    }

    // --- 靜態檔案:網頁本體(HTML/CSS/JS/圖片) ---
    const relativePath = pathname === "/" ? "order-page.html" : pathname.replace(/^\/+/, "");
    const filePath = path.resolve(PUBLIC_DIR, relativePath);
    const isInsidePublicDir = filePath.startsWith(PUBLIC_DIR + path.sep);

    if (isInsidePublicDir && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const content = fs.readFileSync(filePath);
      res.writeHead(200, { "Content-Type": getContentType(filePath) });
      return res.end(content);
    }

    // --- 找不到對應的路徑或檔案 ---
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("404 Not Found");

  } catch (err) {
    console.error("Server error:", err);
    sendJson(res, 500, { error: "Internal server error" });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
});
