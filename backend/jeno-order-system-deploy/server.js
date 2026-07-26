// ============================================
// JÉNO Pâtisserie & Café — Backend Server
// 使用 Node.js 內建的 http 模組,不依賴外部套件
// ============================================


const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");


const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";


const PRODUCTS_FILE = path.join(__dirname, "data", "products.json");
const ORDERS_FILE = path.join(__dirname, "data", "orders.json");
const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOADS_DIR = path.join(PUBLIC_DIR, "uploads");
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ADMIN_SESSION_HOURS = 12;
const adminSessions = new Map();
const loginAttempts = new Map();


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

function parseCookies(req) {
  const cookies = {};
  for (const part of (req.headers.cookie || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) {
      cookies[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return cookies;
}

function secureEqual(actual, expected) {
  const actualBuffer = Buffer.from(String(actual || ""));
  const expectedBuffer = Buffer.from(String(expected || ""));
  return actualBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function getAdminSession(req) {
  const token = parseCookies(req).jeno_admin_session;
  if (!token) return null;
  const session = adminSessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    if (token) adminSessions.delete(token);
    return null;
  }
  return session;
}

function requireAdmin(req, res) {
  if (getAdminSession(req)) return true;
  sendJson(res, 401, { error: "Admin login required." });
  return false;
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
  res.end();
}

function loginAttemptKey(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown")
    .split(",")[0].trim();
}


// 讀取 POST 請求的內容(request body)
function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 8 * 1024 * 1024) {
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
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
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

    // --- 管理員登入 ---
    if (pathname === "/api/admin/login" && req.method === "POST") {
      if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
        return sendJson(res, 503, {
          error: "Admin login is not configured. Set ADMIN_USERNAME and ADMIN_PASSWORD.",
        });
      }

      const attemptKey = loginAttemptKey(req);
      const attempt = loginAttempts.get(attemptKey);
      if (attempt && attempt.blockedUntil > Date.now()) {
        return sendJson(res, 429, { error: "Too many attempts. Try again in 15 minutes." });
      }

      const body = await readRequestBody(req);
      if (!secureEqual(body.username, ADMIN_USERNAME) ||
          !secureEqual(body.password, ADMIN_PASSWORD)) {
        const failures = attempt && attempt.startedAt > Date.now() - 15 * 60 * 1000
          ? attempt.failures + 1
          : 1;
        loginAttempts.set(attemptKey, {
          failures,
          startedAt: failures === 1 ? Date.now() : attempt.startedAt,
          blockedUntil: failures >= 5 ? Date.now() + 15 * 60 * 1000 : 0,
        });
        return sendJson(res, 401, { error: "Incorrect username or password." });
      }

      loginAttempts.delete(attemptKey);
      const token = crypto.randomBytes(32).toString("hex");
      const expiresAt = Date.now() + ADMIN_SESSION_HOURS * 60 * 60 * 1000;
      adminSessions.set(token, { username: ADMIN_USERNAME, expiresAt });
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": "jeno_admin_session=" + token +
          "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" +
          (ADMIN_SESSION_HOURS * 60 * 60),
        "Cache-Control": "no-store",
      });
      return res.end(JSON.stringify({ authenticated: true }));
    }

    if (pathname === "/api/admin/session" && req.method === "GET") {
      const session = getAdminSession(req);
      return sendJson(res, session ? 200 : 401, {
        authenticated: Boolean(session),
        username: session ? session.username : undefined,
      });
    }

    if (pathname === "/api/admin/logout" && req.method === "POST") {
      const token = parseCookies(req).jeno_admin_session;
      if (token) adminSessions.delete(token);
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": "jeno_admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
        "Cache-Control": "no-store",
      });
      return res.end(JSON.stringify({ authenticated: false }));
    }

    if (pathname === "/admin.html" && req.method === "GET" && !getAdminSession(req)) {
      return redirect(res, "/login.html");
    }


    // --- API: 取得所有商品 ---
    if (pathname === "/api/products" && req.method === "GET") {
      const products = readJsonFile(PRODUCTS_FILE);
      return sendJson(res, 200, products);
    }


    // --- API: 上傳商品圖片（展示版；正式環境建議改用物件儲存） ---
    if (pathname === "/api/uploads" && req.method === "POST") {
      if (!requireAdmin(req, res)) return;
      const body = await readRequestBody(req);
      const match = typeof body.data === "string"
        ? body.data.match(/^data:(image\/(?:png|jpeg|webp|gif));base64,([A-Za-z0-9+/=]+)$/)
        : null;


      if (!match) {
        return sendJson(res, 400, { error: "Only PNG, JPEG, WebP, and GIF images are allowed." });
      }


      const extensionByType = {
        "image/png": "png",
        "image/jpeg": "jpg",
        "image/webp": "webp",
        "image/gif": "gif",
      };
      const imageBuffer = Buffer.from(match[2], "base64");


      if (imageBuffer.length === 0 || imageBuffer.length > 5 * 1024 * 1024) {
        return sendJson(res, 400, { error: "Image must be smaller than 5 MB." });
      }


      const safeStem = String(body.filename || "product")
        .replace(/\.[^.]+$/, "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/(^-|-$)/g, "")
        .slice(0, 40) || "product";
      const fileName = safeStem + "-" + Date.now() + "." + extensionByType[match[1]];
      fs.writeFileSync(path.join(UPLOADS_DIR, fileName), imageBuffer);


      return sendJson(res, 201, { image: "/uploads/" + fileName });
    }


    // --- API: 新增商品 ---
    if (pathname === "/api/products" && req.method === "POST") {
      if (!requireAdmin(req, res)) return;
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
        description: body.description || "",
        image: body.image || "",
        optionType: body.optionType || "quantity",
        options: Array.isArray(body.options) ? body.options : [],
      };


      products.push(newProduct);
      writeJsonFile(PRODUCTS_FILE, products);


      return sendJson(res, 201, { message: "Product added", product: newProduct });
    }


    // --- API: 編輯商品(網址例如 /api/products/item1) ---
    if (pathname.startsWith("/api/products/") && req.method === "PUT") {
      if (!requireAdmin(req, res)) return;
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
        ...(body.description !== undefined && { description: String(body.description) }),
        ...(body.image !== undefined && { image: String(body.image) }),
        ...(body.optionType !== undefined && { optionType: String(body.optionType) }),
        ...(Array.isArray(body.options) && {
          options: body.options.map((option) => ({
            value: String(option.value),
            label: String(option.label),
            price: Number(option.price),
          })),
        }),
      };


      writeJsonFile(PRODUCTS_FILE, products);


      return sendJson(res, 200, { message: "Product updated", product: products[index] });
    }


    // --- API: 刪除商品(網址例如 /api/products/item1) ---
    if (pathname.startsWith("/api/products/") && req.method === "DELETE") {
      if (!requireAdmin(req, res)) return;
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
      if (!body.customer || !body.customer.name || !body.customer.phone || !body.customer.email) {
        return sendJson(res, 400, { error: "Customer name, phone, and email are required." });
      }
      if (!body.fulfillment || !body.fulfillment.method || !body.fulfillment.date) {
        return sendJson(res, 400, { error: "Fulfillment method and date are required." });
      }
      if (body.fulfillment.method === "delivery" && !body.fulfillment.address) {
        return sendJson(res, 400, { error: "Delivery address is required." });
      }


      const orders = readJsonFile(ORDERS_FILE);
      const initialStatuses = [
        "awaiting_transfer", "transfer_submitted", "payment_confirmed",
        "preparing", "ready", "completed", "cancelled",
      ];


      const newOrder = {
        id: "JENO-" + Date.now(),
        items: body.items,
        total: Number(body.total) || 0,
        customer: body.customer,
        fulfillment: body.fulfillment,
        paymentMethod: "etransfer",
        payment: null,
        createdAt: new Date().toISOString(),
        status: initialStatuses.includes(body.status) ? body.status : "awaiting_transfer",
      };


      orders.push(newOrder);
      writeJsonFile(ORDERS_FILE, orders);


      return sendJson(res, 201, { message: "Order received", order: newOrder });
    }


    // --- API: 取得所有訂單(給店家後台看的) ---
    if (pathname === "/api/orders" && req.method === "GET") {
      if (!requireAdmin(req, res)) return;
      const orders = readJsonFile(ORDERS_FILE);
      return sendJson(res, 200, orders);
    }

    if (/^\/api\/orders\/[^/]+$/.test(pathname) && req.method === "PUT") {
      if (!requireAdmin(req, res)) return;
      const id = decodeURIComponent(pathname.split("/")[3]);
      const body = await readRequestBody(req);
      const allowedStatuses = [
        "awaiting_transfer", "transfer_submitted", "payment_confirmed",
        "preparing", "ready", "completed", "cancelled", "received",
      ];
      if (!body.items || Object.keys(body.items).length === 0 || !body.customer ||
          !body.customer.name || !body.customer.phone || !body.customer.email ||
          !body.fulfillment || !body.fulfillment.date ||
          !allowedStatuses.includes(body.status)) {
        return sendJson(res, 400, { error: "Complete order information is required." });
      }
      const orders = readJsonFile(ORDERS_FILE);
      const order = orders.find((item) => item.id === id);
      if (!order) return sendJson(res, 404, { error: "Order not found." });
      order.items = body.items;
      order.total = Number(body.total) || 0;
      order.customer = body.customer;
      order.fulfillment = body.fulfillment;
      order.status = body.status;
      order.updatedAt = new Date().toISOString();
      writeJsonFile(ORDERS_FILE, orders);
      return sendJson(res, 200, { message: "Order updated", order });
    }

    if (/^\/api\/orders\/[^/]+$/.test(pathname) && req.method === "DELETE") {
      if (!requireAdmin(req, res)) return;
      const id = decodeURIComponent(pathname.split("/")[3]);
      const orders = readJsonFile(ORDERS_FILE);
      const filtered = orders.filter((item) => item.id !== id);
      if (filtered.length === orders.length) {
        return sendJson(res, 404, { error: "Order not found." });
      }
      writeJsonFile(ORDERS_FILE, filtered);
      return sendJson(res, 200, { message: "Order deleted" });
    }


    // --- API: 顧客提交 e-Transfer 資料 ---
    if (/^\/api\/orders\/[^/]+\/payment$/.test(pathname) && req.method === "PATCH") {
      const id = decodeURIComponent(pathname.split("/")[3]);
      const body = await readRequestBody(req);
      const transfer = body.transfer || {};


      if (!transfer.senderName || !transfer.senderEmail || !transfer.date ||
          !transfer.reference || !Number.isFinite(Number(transfer.amount)) ||
          Number(transfer.amount) <= 0) {
        return sendJson(res, 400, { error: "Complete transfer information is required." });
      }


      const orders = readJsonFile(ORDERS_FILE);
      const order = orders.find((item) => item.id === id);


      if (!order) {
        return sendJson(res, 404, { error: "Order not found." });
      }


      order.payment = {
        senderName: String(transfer.senderName),
        senderEmail: String(transfer.senderEmail),
        date: String(transfer.date),
        amount: Number(transfer.amount),
        reference: String(transfer.reference),
        submittedAt: new Date().toISOString(),
      };
      order.status = "transfer_submitted";
      writeJsonFile(ORDERS_FILE, orders);
      return sendJson(res, 200, { message: "Transfer information submitted", order });
    }


    // --- API: 更新訂單狀態 ---
    if (pathname.startsWith("/api/orders/") && req.method === "PATCH") {
      if (!requireAdmin(req, res)) return;
      const id = decodeURIComponent(pathname.split("/api/orders/")[1]);
      const body = await readRequestBody(req);
      const allowedStatuses = [
        "awaiting_transfer",
        "transfer_submitted",
        "payment_confirmed",
        "preparing",
        "ready",
        "completed",
        "cancelled",
      ];


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
