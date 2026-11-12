'use strict';
/* ============================================================
   M1li server — عدّاد المشاهدات واللايكات والمتابعين + حماية من الغش
   بدون أي مكتبة خارجية. يحتاج Node.js 22.13 أو أحدث (فيه SQLite مدمج).
   تشغيل:  ADMIN_KEY=... SECRET=... node server.js
   ============================================================ */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const tls = require('node:tls');
const zlib = require('node:zlib');
const { DatabaseSync } = require('node:sqlite');

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8'
};
const BOT_RE = /bot|crawl|spider|slurp|headless|phantom|selenium|puppeteer|playwright|curl\/|wget|python-requests|python-urllib|go-http-client|java\/|scrapy|axios|node-fetch|undici|libwww/i;
const AD_RE = /^[A-Za-z0-9_\-.:]{1,64}$/;
const DEV_RE = /^[A-Za-z0-9_\-]{8,64}$/;

function loadConfig(over) {
  const e = process.env;
  const secret = e.SECRET || crypto.randomBytes(32).toString('hex');
  return Object.assign({
    port: Number(e.PORT) || 3000,
    host: e.HOST || '0.0.0.0',
    dbPath: e.DB_PATH || path.join(__dirname, 'data', 'm1li.db'),
    staticDir: e.STATIC_DIR || path.join(__dirname, '..', 'dist'),
    adminKey: e.ADMIN_KEY || '',
    adminEmail: String(e.ADMIN_EMAIL || '').trim().toLowerCase(),   // دخول الإدارة بإيميل + كلمة مرور (اختياري)
    adminPhone: normPhone(e.ADMIN_PHONE || ''),                      // (اختياري) دخول الإدارة برقم الهاتف + نفس كلمة المرور
    adminPassword: e.ADMIN_PASSWORD || '',                           // نص عادي (12 حرف على الأقل) — أو الأفضل ADMIN_PASSWORD_HASH
    adminPasswordHash: e.ADMIN_PASSWORD_HASH || '',                  // 'scrypt$salt$hash' (node hash-password.js)
    adminSessionHours: Number(e.ADMIN_SESSION_HOURS) || 8,
    /* --- إيميل (Gmail SMTP): كود الدخول للأدمن + إشعار عند نشر تطبيق جديد --- */
    smtpHost: e.SMTP_HOST || 'smtp.gmail.com',
    smtpPort: Number(e.SMTP_PORT) || 465,           // 465 = TLS مباشر (Gmail)
    smtpSecure: e.SMTP_SECURE === undefined ? true : e.SMTP_SECURE !== '0',
    smtpUser: e.SMTP_USER || '',
    smtpPass: String(e.SMTP_PASS || '').replace(/\s+/g, ''),   // «App Password» من Google (16 حرف)
    mailFrom: e.MAIL_FROM || '',
    notifyEmail: String(e.ADMIN_NOTIFY_EMAIL || e.ADMIN_EMAIL || '').trim().toLowerCase(),
    publicUrl: String(e.PUBLIC_URL || '').replace(/\/+$/, ''),
    mailer: null,                                    // (للاختبارات) دالة بديلة للإرسال
    secret: secret, secretFromEnv: !!e.SECRET,
    ipSalt: e.IP_SALT || secret,
    allowedOrigin: e.ALLOWED_ORIGIN || '*',   // ضع نطاق متجرك الحقيقي، مثال: https://m1li.example.com
    trustProxy: e.TRUST_PROXY === '1',        // فعّله إذا كان السيرفر خلف nginx/Caddy
    debug: e.DEBUG === '1',                    // يُظهر سبب رفض المشاهدة في الاستجابة (للتجريب فقط)
    minVisibleMs: 1400,                        // أقل مدة بين طلب التوكن وإرسال المشاهدة
    tokenMaxAgeMs: 15 * 60 * 1000,
    ipRatePerMin: 300,                         // حد الطلبات لكل IP في الدقيقة
    maxDevicesPerIpAdDay: 20,                  // أقصى عدد أجهزة مختلفة من نفس IP لنفس الإعلان في اليوم
    maxAdsPerDeviceDay: 150,                   // أقصى عدد إعلانات يشاهدها جهاز واحد في اليوم
    otpMode: e.OTP_MODE || '',                 // 'console' للتجريب فقط (يطبع الرمز في سجل السيرفر)
    otpWebhookUrl: e.OTP_WEBHOOK_URL || '',    // بوابة الإرسال (SMS أو واتساب) — انظر server/README.md
    otpWebhookAuth: e.OTP_WEBHOOK_AUTH || (e.OTP_WEBHOOK_TOKEN ? 'Bearer ' + e.OTP_WEBHOOK_TOKEN : ''),
    otpWebhookType: e.OTP_WEBHOOK_TYPE === 'form' ? 'form' : 'json',
    otpWebhookBody: e.OTP_WEBHOOK_BODY || '',  // قالب اختياري فيه {to} {phone} {code} {message} {channel}
    otpChannel: e.OTP_CHANNEL || 'sms',
    otpCountries: String(e.OTP_COUNTRIES || '212').split(',').map(function (x) { return x.trim(); }).filter(Boolean),
    otpDailyMax: Number(e.OTP_DAILY_MAX) || 300, // سقف يومي لعدد الرسائل (حماية من استنزاف الرصيد)
    otpSender: null,
    otpTtlMs: 5 * 60 * 1000, otpCooldownMs: 60 * 1000, otpPerPhoneHour: 3, otpPerIpHour: 10, otpMaxAttempts: 5,
    registerPerIpHour: 5,                      // أقصى عدد حسابات جديدة من نفس IP في الساعة
    sessionDays: 30,
    /* --- تسجيل الدخول بـ Google/Gmail --- */
    googleClientId: e.GOOGLE_CLIENT_ID || '',   // من Google Cloud Console → OAuth client (Web)
    googleJwks: null,                            // (للاختبارات) دالة بديلة تجلب مفاتيح Google
    /* --- «اربح مع m1li»: نظام النقاط (كلها قابلة للتعديل من .env) --- */
    earnPointsPerVideo: Number(e.EARN_POINTS_PER_VIDEO) || 50,     // نقاط افتراضية عند قبول فيديو
    earnMaxPointsPerVideo: Number(e.EARN_MAX_POINTS_PER_VIDEO) || 500, // سقف ما يقدر الأدمن يمنحه لفيديو واحد
    earnPointsPerMad: Number(e.EARN_POINTS_PER_MAD) || 100,        // 100 نقطة = 1 درهم  (1000 نقطة = 10 د.م)
    earnMinPayoutPoints: Number(e.EARN_MIN_PAYOUT_POINTS) || 5000, // الحد الأدنى للسحب (= 50 د.م)
    earnHoldDays: e.EARN_HOLD_DAYS === undefined || e.EARN_HOLD_DAYS === '' ? 3 : Number(e.EARN_HOLD_DAYS), // النقاط تبقى «معلّقة» هاد المدة بعد القبول
    earnSubmitPerDay: Number(e.EARN_SUBMIT_PER_DAY) || 3,          // أقصى فيديوهات يرسلها حساب في اليوم
    earnMaxPending: Number(e.EARN_MAX_PENDING) || 5,               // أقصى فيديوهات قيد المراجعة لكل حساب
    earnMinAccountHours: e.EARN_MIN_ACCOUNT_HOURS === undefined || e.EARN_MIN_ACCOUNT_HOURS === '' ? 24 : Number(e.EARN_MIN_ACCOUNT_HOURS), // عمر الحساب قبل أول إرسال
    maxAppsPerUser: 30,                        // أقصى عدد تطبيقات نشطة لكل ناشر
    publishPerHour: 10,
    updatePerHour: 20,                         // تحديثات التطبيقات المنشورة لكل ناشر في الساعة
    publishDelayMin: e.PUBLISH_DELAY_MIN === undefined || e.PUBLISH_DELAY_MIN === '' ? 60 : Number(e.PUBLISH_DELAY_MIN), // التطبيق الجديد يظهر للجميع بعد هذه المدة (0 = فوراً)
    maxUploadMb: Number(e.MAX_UPLOAD_MB) || 60,   // أقصى حجم لملف APK/ZIP المرفوع
    uploadsPerHour: 40,                        // صور + ZIP + PDF
    maxImageMb: Number(e.MAX_IMAGE_MB) || 4,
    maxPdfMb: Number(e.MAX_PDF_MB) || 40,
    appsDir: e.APPS_DIR || path.join(__dirname, 'data', 'apps'),   // تطبيقات الويب المستخرجة من ZIP
    autoPublish: e.AUTO_PUBLISH !== '0',       // التطبيق الذي يجتاز الفحص الآلي بلا تحذيرات يظهر فوراً (AUTO_PUBLISH=0 يعيد مهلة publishDelayMin)
    listingsPerHour: 20, maxListingsPerUser: 60,
    uploadDir: e.UPLOAD_DIR || path.join(__dirname, 'data', 'uploads'),
    publishRequireGoogle: e.PUBLISH_REQUIRE_GOOGLE === '1',   // (اختياري) النشر يتطلب حساب Google — يلزم AUTH_MODE=phone
    nameAuth: e.AUTH_MODE !== 'phone',        // الافتراضي: حساب = اسم + كود فقط (بلا هاتف ولا Google). AUTH_MODE=phone للنمط القديم
    anomalyIntervalMs: 60 * 1000,
    anomalyWindowMs: 10 * 60 * 1000,
    anomalyMinViews: 30,                       // لا نفحص الشذوذ تحت هذا العدد من المشاهدات في النافذة
    anomalySigma: 4,                           // كم انحراف معياري فوق المعدل يعتبر شاذاً
    ipConcentration: 0.6,                      // إذا جاءت أكثر من 60% من المشاهدات من IP واحد
    ipConcentrationMin: 20
  }, over || {});
}

function httpErr(status, code) { const e = new Error(code); e.status = status; e.code = code; return e; }
/* رقم الهاتف الموحّد: مغربي (06/07/05 أو 212…) أو دولي بصيغة +… / 00… */
function normPhone(raw) {
  let s = String(raw || '').trim();
  if (s.length > 25) return '';
  const intl = /^(\+|00)/.test(s);
  s = s.replace(/[\s().\-]/g, '').replace(/^\+/, '').replace(/^00/, '');
  if (!/^\d+$/.test(s)) return '';
  if (!intl && /^0[5-7]\d{8}$/.test(s)) return '212' + s.slice(1);
  if (/^212[5-7]\d{8}$/.test(s)) return s;
  if (intl && /^[1-9]\d{7,14}$/.test(s) && !/^212/.test(s)) return s;
  return '';
}
const RESERVED_NAME = /^(فريق\s*)?m1li$|^فريق m1li$|^مطور مجهول$|^admin$|^administrator$|^support$/i;
const APP_CATS = ['games', 'tools', 'productivity', 'lifestyle'];
function today() { return new Date().toISOString().slice(0, 10); }

function createApp(over) {
  const cfg = loadConfig(over);
  if (cfg.dbPath !== ':memory:') fs.mkdirSync(path.dirname(cfg.dbPath), { recursive: true });
  const db = new DatabaseSync(cfg.dbPath);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS views (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ad_id TEXT NOT NULL, device_id TEXT NOT NULL, day TEXT NOT NULL,
      ip_hash TEXT NOT NULL, ua TEXT,
      valid INTEGER NOT NULL, reason TEXT, created_at INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uq_valid_view ON views(ad_id, device_id, day) WHERE valid = 1;
    CREATE INDEX IF NOT EXISTS ix_views_ad ON views(ad_id, valid);
    CREATE INDEX IF NOT EXISTS ix_views_time ON views(created_at);
    CREATE INDEX IF NOT EXISTS ix_views_dev ON views(device_id, day);
    CREATE TABLE IF NOT EXISTS likes (
      ad_id TEXT NOT NULL, device_id TEXT NOT NULL, created_at INTEGER NOT NULL,
      PRIMARY KEY (ad_id, device_id)
    );
    CREATE TABLE IF NOT EXISTS follows (
      dev TEXT NOT NULL, device_id TEXT NOT NULL, created_at INTEGER NOT NULL,
      PRIMARY KEY (dev, device_id)
    );
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ad_id TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT,
      created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open'
    );
    CREATE INDEX IF NOT EXISTS ix_alerts_ad ON alerts(ad_id, status);
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
      salt TEXT NOT NULL, pass_hash TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS apps (
      id TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
      title TEXT NOT NULL, category TEXT NOT NULL, desc TEXT NOT NULL, icon TEXT NOT NULL,
      type TEXT NOT NULL, code TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '',
      apk_url TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_apps_user ON apps(user_id, status);
    CREATE INDEX IF NOT EXISTS ix_apps_time ON apps(status, created_at);
  `);
  ['updated_at INTEGER NOT NULL DEFAULT 0', 'publish_at INTEGER NOT NULL DEFAULT 0'].forEach(function (c) {
    try { db.exec('ALTER TABLE apps ADD COLUMN ' + c); } catch (e) { /* العمود موجود */ }
  });
  db.exec(`CREATE TABLE IF NOT EXISTS otps (
    phone TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, last_sent INTEGER NOT NULL
  )`);
  ["images TEXT NOT NULL DEFAULT '[]'", "report TEXT NOT NULL DEFAULT ''"].forEach(function (c) {
    try { db.exec('ALTER TABLE apps ADD COLUMN ' + c); } catch (e) { /* العمود موجود */ }
  });
  db.exec(`CREATE TABLE IF NOT EXISTS listings (
    id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, kind TEXT NOT NULL,
    title TEXT NOT NULL, desc TEXT NOT NULL DEFAULT '', price REAL NOT NULL DEFAULT 0, city TEXT NOT NULL DEFAULT '', whatsapp TEXT NOT NULL DEFAULT '',
    images TEXT NOT NULL DEFAULT '[]', file_url TEXT NOT NULL DEFAULT '', extra TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active', created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS ix_listings_kind ON listings(kind, status, created_at);
  CREATE INDEX IF NOT EXISTS ix_listings_user ON listings(user_id, status);`);
  try { db.exec('ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 0'); } catch (e) { /* العمود موجود */ }
  try { db.exec('ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT \'\''); } catch (e) { /* العمود موجود */ }
  try { db.exec("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''"); } catch (e) { /* العمود موجود */ }
  try { db.exec("ALTER TABLE users ADD COLUMN google_sub TEXT NOT NULL DEFAULT ''"); } catch (e) { /* العمود موجود */ }
  db.exec("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_google ON users(google_sub) WHERE google_sub<>''");
  try { db.exec('ALTER TABLE users ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0'); } catch (e) { /* العمود موجود */ }
  db.exec(`
    CREATE TABLE IF NOT EXISTS video_submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL, platform TEXT NOT NULL,
      video_url TEXT NOT NULL, canon_url TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL DEFAULT 'pending',
      points_awarded INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL, reviewed_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS ix_vs_user ON video_submissions(user_id, created_at);
    CREATE INDEX IF NOT EXISTS ix_vs_status ON video_submissions(status, created_at);
    CREATE TABLE IF NOT EXISTS points_ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL, delta INTEGER NOT NULL, kind TEXT NOT NULL,
      ref_id INTEGER, available_at INTEGER NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_pl_user ON points_ledger(user_id);
    CREATE UNIQUE INDEX IF NOT EXISTS uq_pl_award ON points_ledger(kind, ref_id) WHERE kind IN ('award','revoke','payout','refund');
    CREATE TABLE IF NOT EXISTS payout_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL, points INTEGER NOT NULL, amount_mad REAL NOT NULL,
      method TEXT NOT NULL, holder TEXT NOT NULL, account TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL, processed_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS ix_po_user ON payout_requests(user_id, status);
    CREATE TABLE IF NOT EXISTS shop_orders (
      id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'new',
      name TEXT NOT NULL, phone TEXT NOT NULL, city TEXT NOT NULL, addr TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
      items TEXT NOT NULL, sub REAL NOT NULL, fee REAL NOT NULL, disc REAL NOT NULL, total REAL NOT NULL, coupon TEXT NOT NULL DEFAULT '',
      ip_hash TEXT NOT NULL, client_ts INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS ix_so_status ON shop_orders(status, created_at);
    CREATE INDEX IF NOT EXISTS ix_so_ip ON shop_orders(ip_hash, created_at);
  `);

  const q = {
    validView: db.prepare('SELECT 1 AS x FROM views WHERE ad_id=? AND device_id=? AND day=? AND valid=1'),
    insertView: db.prepare('INSERT INTO views (ad_id,device_id,day,ip_hash,ua,valid,reason,created_at) VALUES (?,?,?,?,?,?,?,?)'),
    ipDevices: db.prepare('SELECT COUNT(*) AS n FROM views WHERE ad_id=? AND day=? AND ip_hash=? AND valid=1'),
    devAds: db.prepare('SELECT COUNT(DISTINCT ad_id) AS n FROM views WHERE device_id=? AND day=?'),
    openAlert: db.prepare("SELECT id FROM alerts WHERE ad_id=? AND status='open' LIMIT 1"),
    hasActivity: db.prepare('SELECT 1 AS x FROM views WHERE device_id=? AND valid=1 LIMIT 1'),
    likeGet: db.prepare('SELECT 1 AS x FROM likes WHERE ad_id=? AND device_id=?'),
    likeAdd: db.prepare('INSERT OR IGNORE INTO likes (ad_id,device_id,created_at) VALUES (?,?,?)'),
    likeDel: db.prepare('DELETE FROM likes WHERE ad_id=? AND device_id=?'),
    likeCount: db.prepare('SELECT COUNT(*) AS n FROM likes WHERE ad_id=?'),
    followGet: db.prepare('SELECT 1 AS x FROM follows WHERE dev=? AND device_id=?'),
    followAdd: db.prepare('INSERT OR IGNORE INTO follows (dev,device_id,created_at) VALUES (?,?,?)'),
    followDel: db.prepare('DELETE FROM follows WHERE dev=? AND device_id=?'),
    followCount: db.prepare('SELECT COUNT(*) AS n FROM follows WHERE dev=?'),
    recentAds: db.prepare("SELECT ad_id, COUNT(*) AS n FROM views WHERE created_at>=? AND (valid=1 OR reason='held') GROUP BY ad_id"),
    topIp: db.prepare("SELECT COUNT(*) AS n FROM views WHERE ad_id=? AND created_at>=? AND (valid=1 OR reason='held') GROUP BY ip_hash ORDER BY n DESC LIMIT 1"),
    buckets: db.prepare('SELECT CAST((? - created_at) / ? AS INTEGER) AS b, COUNT(*) AS n FROM views WHERE ad_id=? AND valid=1 AND created_at>=? AND created_at<? GROUP BY b'),
    holdRecent: db.prepare("UPDATE views SET valid=0, reason='held' WHERE ad_id=? AND created_at>=? AND valid=1"),
    insertAlert: db.prepare('INSERT INTO alerts (ad_id,kind,detail,created_at) VALUES (?,?,?,?)'),
    alertGet: db.prepare('SELECT * FROM alerts WHERE id=?'),
    alertSet: db.prepare('UPDATE alerts SET status=? WHERE id=?'),
    alertList: db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT 100'),
    alertListByStatus: db.prepare('SELECT * FROM alerts WHERE status=? ORDER BY id DESC LIMIT 100'),
    releaseHeld: db.prepare("UPDATE OR IGNORE views SET valid=1, reason=NULL WHERE ad_id=? AND reason='held'"),
    sumViews: db.prepare("SELECT valid, COALESCE(reason,'ok') AS r, COUNT(*) AS n FROM views GROUP BY valid, r"),
    sumLikes: db.prepare('SELECT COUNT(*) AS n FROM likes'),
    sumFollows: db.prepare('SELECT COUNT(*) AS n FROM follows'),
    userByPhone: db.prepare('SELECT * FROM users WHERE phone=?'),
    userByName: db.prepare('SELECT * FROM users WHERE lower(name)=lower(?)'),
    userInsert: db.prepare('INSERT INTO users (phone,name,salt,pass_hash,created_at,verified) VALUES (?,?,?,?,?,?)'),
    userByGoogle: db.prepare('SELECT * FROM users WHERE google_sub=?'),
    userInsertGoogle: db.prepare("INSERT INTO users (phone,name,salt,pass_hash,created_at,verified,email,google_sub) VALUES (?,?,?,?,?,1,?,?)"),
    sessAdd: db.prepare('INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)'),
    sessGet: db.prepare('SELECT u.id AS id, u.name AS name, u.phone AS phone, u.email AS email, u.verified AS verified FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?'),
    sessDel: db.prepare('DELETE FROM sessions WHERE token_hash=?'),
    sessTrim: db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC LIMIT 10)'),
    sessPurge: db.prepare('DELETE FROM sessions WHERE expires_at<=?'),
    userCount: db.prepare('SELECT COUNT(*) AS n FROM users'),
    userList: db.prepare('SELECT id, phone, email, name, verified, created_at, last_seen FROM users ORDER BY id DESC LIMIT 200'),
    userSeen: db.prepare('UPDATE users SET last_seen=? WHERE id=? AND last_seen<?'),
    userMetrics: db.prepare('SELECT COUNT(*) AS total, COALESCE(SUM(created_at>?),0) AS new7, COALESCE(SUM(created_at>?),0) AS new30, COALESCE(SUM(last_seen>?),0) AS active7, COALESCE(SUM(last_seen>?),0) AS active30, COALESCE(SUM(last_seen>? AND created_at<=?),0) AS returning7, COALESCE(SUM(created_at<=?),0) AS older7 FROM users'),
    otpGet: db.prepare('SELECT * FROM otps WHERE phone=?'),
    otpSet: db.prepare('INSERT OR REPLACE INTO otps (phone,code_hash,expires_at,attempts,last_sent) VALUES (?,?,?,0,?)'),
    otpDel: db.prepare('DELETE FROM otps WHERE phone=?'),
    otpAttempt: db.prepare('UPDATE otps SET attempts=attempts+1 WHERE phone=?'),
    otpPurge: db.prepare('DELETE FROM otps WHERE expires_at<?'),
    userVerify: db.prepare('UPDATE users SET verified=1 WHERE id=?'),
    nameTaken: db.prepare('SELECT 1 AS x FROM users WHERE lower(name)=lower(?)'),
    bioSet: db.prepare('UPDATE users SET bio=? WHERE id=?'),
    appInsert: db.prepare('INSERT INTO apps (id,user_id,title,category,desc,icon,type,code,url,apk_url,version,created_at,publish_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'),
    appUpdate: db.prepare('UPDATE apps SET title=?,category=?,desc=?,icon=?,code=?,url=?,apk_url=?,version=?,updated_at=? WHERE id=? AND user_id=?'),
    appExtra: db.prepare('UPDATE apps SET images=?, report=? WHERE id=?'),
    appApprove: db.prepare("UPDATE apps SET publish_at=0 WHERE id=? AND status='active'"),
    appList: db.prepare("SELECT a.id,a.user_id,a.title,a.category,a.desc,a.icon,a.type,a.url,a.apk_url,a.version,a.created_at,a.publish_at,a.updated_at,a.images,(a.code<>'') AS has_code,u.name AS developer,u.bio AS bio FROM apps a JOIN users u ON u.id=a.user_id WHERE a.status='active' AND (a.publish_at<=? OR a.user_id=?) ORDER BY a.created_at DESC LIMIT 500"),
    appGet: db.prepare("SELECT a.*, u.name AS developer, u.bio AS bio FROM apps a JOIN users u ON u.id=a.user_id WHERE a.id=? AND a.status='active'"),
    appOwn: db.prepare("SELECT id, user_id FROM apps WHERE id=? AND status='active'"),
    appDel: db.prepare('DELETE FROM apps WHERE id=?'),
    appCount: db.prepare("SELECT COUNT(*) AS n FROM apps WHERE user_id=? AND status='active'"),
    appRecent: db.prepare('SELECT COUNT(*) AS n FROM apps WHERE user_id=? AND created_at>?'),
    appRemove: db.prepare("UPDATE apps SET status='removed' WHERE id=? AND status='active'"),
    appAdminList: db.prepare('SELECT a.id,a.title,a.type,a.category,a.desc,a.url,a.apk_url,a.version,a.status,a.created_at,a.publish_at,u.phone,u.email,u.name FROM apps a JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 300'),
    sumOpen: db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE status='open'")
  };

  const eq = {
    vsInsert: db.prepare('INSERT INTO video_submissions (user_id,platform,video_url,canon_url,created_at) VALUES (?,?,?,?,?)'),
    vsByCanon: db.prepare('SELECT id FROM video_submissions WHERE canon_url=?'),
    vsGet: db.prepare('SELECT * FROM video_submissions WHERE id=?'),
    vsMine: db.prepare('SELECT id,platform,video_url,status,points_awarded,note,created_at FROM video_submissions WHERE user_id=? ORDER BY id DESC LIMIT 50'),
    vsPendingCount: db.prepare("SELECT COUNT(*) AS n FROM video_submissions WHERE user_id=? AND status='pending'"),
    vsSince: db.prepare('SELECT COUNT(*) AS n FROM video_submissions WHERE user_id=? AND created_at>?'),
    vsReview: db.prepare("UPDATE video_submissions SET status=?, points_awarded=?, note=?, reviewed_at=? WHERE id=? AND status=?"),
    vsAdminList: db.prepare('SELECT v.id,v.platform,v.video_url,v.status,v.points_awarded,v.note,v.created_at,u.id AS user_id,u.name,u.phone,u.email FROM video_submissions v JOIN users u ON u.id=v.user_id WHERE v.status=? ORDER BY v.id ASC LIMIT 200'),
    userById: db.prepare('SELECT id,name,phone,created_at,verified FROM users WHERE id=?'),
    plAdd: db.prepare('INSERT INTO points_ledger (user_id,delta,kind,ref_id,available_at,created_at) VALUES (?,?,?,?,?,?)'),
    plAvail: db.prepare('SELECT COALESCE(SUM(delta),0) AS n FROM points_ledger WHERE user_id=? AND available_at<=?'),
    plTotal: db.prepare('SELECT COALESCE(SUM(delta),0) AS n FROM points_ledger WHERE user_id=?'),
    poInsert: db.prepare('INSERT INTO payout_requests (user_id,points,amount_mad,method,holder,account,created_at) VALUES (?,?,?,?,?,?,?)'),
    poGet: db.prepare('SELECT * FROM payout_requests WHERE id=?'),
    poMine: db.prepare('SELECT id,points,amount_mad,method,status,note,created_at FROM payout_requests WHERE user_id=? ORDER BY id DESC LIMIT 20'),
    poOpen: db.prepare("SELECT COUNT(*) AS n FROM payout_requests WHERE user_id=? AND status='pending'"),
    poSet: db.prepare('UPDATE payout_requests SET status=?, note=?, processed_at=? WHERE id=? AND status=?'),
    poAdminList: db.prepare('SELECT p.id,p.points,p.amount_mad,p.method,p.holder,p.account,p.status,p.note,p.created_at,u.id AS user_id,u.name,u.phone,u.email FROM payout_requests p JOIN users u ON u.id=p.user_id WHERE p.status=? ORDER BY p.id ASC LIMIT 200'),
    earnStats: db.prepare("SELECT (SELECT COUNT(*) FROM video_submissions WHERE status='pending') AS pending_videos, (SELECT COUNT(*) FROM payout_requests WHERE status='pending') AS pending_payouts, (SELECT COALESCE(SUM(points_awarded),0) FROM video_submissions WHERE status='approved') AS points_awarded")
  };

  /* ---------- أدوات ---------- */
  function clientIp(req) {
    if (cfg.trustProxy) {
      const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
      if (xf) return xf;
    }
    return req.socket.remoteAddress || '0.0.0.0';
  }
  function hashIp(ip) { return crypto.createHash('sha256').update(cfg.ipSalt + '|' + ip).digest('hex').slice(0, 24); }

  function sign(ts, ad, dev) { return crypto.createHmac('sha256', cfg.secret).update(ts + '|' + ad + '|' + dev).digest('base64url').slice(0, 22); }
  function makeToken(ad, dev) { const ts = Date.now(); return ts + '.' + sign(ts, ad, dev); }
  function checkToken(tok, ad, dev) {
    const m = /^(\d{10,15})\.([A-Za-z0-9_\-]{22})$/.exec(String(tok || ''));
    if (!m) return 'bad_token';
    const a = Buffer.from(m[2]), b = Buffer.from(sign(m[1], ad, dev));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return 'bad_token';
    const age = Date.now() - Number(m[1]);
    if (age < cfg.minVisibleMs) return 'too_fast';
    if (age > cfg.tokenMaxAgeMs) return 'expired';
    return 'ok';
  }

  const rate = new Map();   // ip_hash -> [timestamps]
  function rateLimited(ipHash) {
    const now = Date.now(), arr = (rate.get(ipHash) || []).filter(function (t) { return now - t < 60000; });
    arr.push(now); rate.set(ipHash, arr);
    return arr.length > cfg.ipRatePerMin;
  }
  const adminFails = new Map();  // ip_hash -> [timestamps]
  function adminBlocked(ipHash) {
    const now = Date.now(), arr = (adminFails.get(ipHash) || []).filter(function (t) { return now - t < 600000; });
    adminFails.set(ipHash, arr);
    return arr.length >= 10;
  }
  const regTimes = new Map();    // ip_hash -> [timestamps] (تسجيلات ناجحة)
  const pubTimes = new Map();
  const updTimes = new Map(), upTimes = new Map();    // user_id -> [timestamps] (النشر لا يُصفَّر بالحذف)
  const otpPhoneTimes = new Map(), otpIpTimes = new Map();
  let otpDay = { day: '', n: 0 };
  const loginFails = new Map();  // 'p:phone' أو 'i:ip_hash' -> [timestamps]
  function recent(map, key, windowMs) {
    const now = Date.now(), arr = (map.get(key) || []).filter(function (t) { return now - t < windowMs; });
    map.set(key, arr); return arr;
  }
  const cleaner = setInterval(function () {
    const now = Date.now();
    regTimes.forEach(function (arr, k) { if (!arr.length || now - arr[arr.length - 1] > 3600000) regTimes.delete(k); });
    pubTimes.forEach(function (arr, k) { if (!arr.length || now - arr[arr.length - 1] > 3600000) pubTimes.delete(k); });
    loginFails.forEach(function (arr, k) { if (!arr.length || now - arr[arr.length - 1] > 900000) loginFails.delete(k); });
    otpPhoneTimes.forEach(function (arr, k) { if (!arr.length || now - arr[arr.length - 1] > 3600000) otpPhoneTimes.delete(k); });
    otpIpTimes.forEach(function (arr, k) { if (!arr.length || now - arr[arr.length - 1] > 3600000) otpIpTimes.delete(k); });
    submitTimes.forEach(function (arr, k) { if (!arr.length || now - arr[arr.length - 1] > 86400000) submitTimes.delete(k); });
    try { q.sessPurge.run(now); q.otpPurge.run(now); } catch (e) {}
    rate.forEach(function (arr, k) { if (!arr.length || now - arr[arr.length - 1] > 60000) rate.delete(k); });
    adminFails.forEach(function (arr, k) { if (!arr.length || now - arr[arr.length - 1] > 600000) adminFails.delete(k); });
  }, 5 * 60 * 1000);
  cleaner.unref();

  /* ---------- إرسال إيميل (SMTP بسيط بلا مكتبات) ---------- */
  const MAIL_RE = /^[^\s<>"',;]{1,64}@[A-Za-z0-9.\-]{1,200}$/;
  function smtpSend(o) {
    return new Promise(function (resolve, reject) {
      if (!MAIL_RE.test(o.from) || !MAIL_RE.test(o.to)) return reject(new Error('bad_address'));
      const sock = o.secure ? tls.connect({ host: o.host, port: o.port, servername: o.host }) : net.connect({ host: o.host, port: o.port });
      let buf = '', done = false, step = 0;
      const b64 = function (v) { return Buffer.from(String(v)).toString('base64'); };
      const subject = '=?UTF-8?B?' + b64(String(o.subject).replace(/[\r\n]+/g, ' ').slice(0, 200)) + '?=';
      const body = Buffer.from(String(o.text), 'utf8').toString('base64').replace(/(.{76})/g, '$1\r\n');
      const msg = ['From: ' + (o.fromName ? '=?UTF-8?B?' + b64(o.fromName) + '?= ' : '') + '<' + o.from + '>', 'To: <' + o.to + '>', 'Subject: ' + subject,
        'Date: ' + new Date().toUTCString(), 'Message-ID: <' + crypto.randomBytes(12).toString('hex') + '@' + o.host + '>', 'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', body, ''].join('\r\n');
      const steps = [
        { send: 'EHLO m1li', ok: '2' },
        o.pass ? { send: 'AUTH LOGIN', ok: '3' } : null, o.pass ? { send: b64(o.user), ok: '3' } : null, o.pass ? { send: b64(o.pass), ok: '2' } : null,
        { send: 'MAIL FROM:<' + o.from + '>', ok: '2' }, { send: 'RCPT TO:<' + o.to + '>', ok: '2' }, { send: 'DATA', ok: '3' },
        { send: msg + '\r\n.', ok: '2' }, { send: 'QUIT', ok: '2', last: true }
      ].filter(Boolean);
      function finish(err) { if (done) return; done = true; try { sock.destroy(); } catch (x) {} err ? reject(err) : resolve(true); }
      sock.setTimeout(20000, function () { finish(new Error('smtp_timeout')); });
      sock.on('error', function (er) { finish(er); });
      sock.on('close', function () { if (!done) finish(new Error('smtp_closed')); });
      sock.on('data', function (d) {
        buf += d.toString('utf8');
        let m;
        while ((m = /^(?:\d{3}-[^\n]*\n)*(\d{3}) [^\n]*\n/.exec(buf))) {
          buf = buf.slice(m[0].length);
          const code = m[1];
          if (step === 0) { if (code[0] !== '2') return finish(new Error('smtp_' + code)); }
          else { const prev = steps[step - 1]; if (code[0] !== prev.ok) return finish(new Error('smtp_' + code)); if (prev.last) return finish(); }
          if (step >= steps.length) return finish();
          sock.write(steps[step].send + '\r\n'); step++;
        }
      });
    });
  }
  const mailEnabled = !!(cfg.mailer || (cfg.smtpUser && cfg.smtpPass));
  function sendMail(to, subject, text) {
    if (cfg.mailer) return Promise.resolve(cfg.mailer({ to: to, subject: subject, text: text }));
    if (!mailEnabled) return Promise.reject(new Error('mail_disabled'));
    return smtpSend({ host: cfg.smtpHost, port: cfg.smtpPort, secure: cfg.smtpSecure, user: cfg.smtpUser, pass: cfg.smtpPass,
      from: cfg.mailFrom || cfg.smtpUser, fromName: 'm1li', to: to, subject: subject, text: text });
  }
  const notifyTimes = [];
  function notifyNewApp(user, body, id) {
    if (!cfg.notifyEmail || !mailEnabled) return;
    const now = Date.now(); while (notifyTimes.length && now - notifyTimes[0] > 3600000) notifyTimes.shift();
    if (notifyTimes.length >= 30) return;   // سقف الإيميلات فالساعة: ما نغرقوش البريد
    notifyTimes.push(now);
    const clean = function (v, n) { return String(v || '').replace(/[\u0000-\u001f]+/g, ' ').slice(0, n); };
    const lines = ['تطبيق جديد منشور على m1li', '', 'العنوان: ' + clean(body.title, 60), 'الناشر: ' + clean(user.name, 60) + (user.email ? ' <' + user.email + '>' : ''),
      'النوع: ' + clean(body.type, 10) + ' · الفئة: ' + clean(body.category, 20), 'الوصف: ' + clean(body.desc, 300)];
    if (body.type === 'url') lines.push('الرابط: ' + clean(body.url, 300));
    if (body.type === 'apk') lines.push('APK: ' + clean(body.apkUrl, 300));
    if (cfg.publicUrl) lines.push('', 'صفحة الإدارة: ' + cfg.publicUrl + '/earn-admin.html');
    lines.push('', 'المعرّف: ' + id);
    sendMail(cfg.notifyEmail, '🆕 تطبيق جديد: ' + clean(body.title, 60), lines.join('\n')).catch(function (er) { console.error('notify mail:', er && er.message); });
  }
  /* كود دخول الإدارة (6 أرقام) كيوصل للإيميل */
  const adminCode = { hash: '', exp: 0, tries: 0 };
  const codeSends = new Map();   // ip_hash -> [timestamps]
  const globalCodeSends = [];
  function codeHash(c) { return crypto.createHmac('sha256', cfg.secret).update('admincode|' + c).digest(); }
  async function adminCodeSend(body, ipHash) {
    if (!cfg.adminEmail || !mailEnabled) throw httpErr(503, 'admin_mail_disabled');
    const now = Date.now(), mine = (codeSends.get(ipHash) || []).filter(function (t) { return now - t < 600000; });
    while (globalCodeSends.length && now - globalCodeSends[0] > 3600000) globalCodeSends.shift();
    if (mine.length >= 3 || globalCodeSends.length >= 8) throw httpErr(429, 'too_many_attempts');
    const email = String(body.email || '').trim().toLowerCase().slice(0, 200);
    if (crypto.timingSafeEqual(digest(email), digest(cfg.adminEmail))) {
      mine.push(now); codeSends.set(ipHash, mine); globalCodeSends.push(now);
      const code = String(crypto.randomInt(100000, 1000000));
      adminCode.hash = codeHash(code).toString('hex'); adminCode.exp = now + 600000; adminCode.tries = 0;
      try { await sendMail(cfg.adminEmail, 'كود دخول إدارة m1li: ' + code, 'كود الدخول: ' + code + '\n\nصالح 10 دقائق ويُستعمل مرة واحدة.\nإذا ما طلبتوش، تجاهل هاد الرسالة.'); }
      catch (er) { console.error('admin code mail:', er && er.message); adminCode.hash = ''; throw httpErr(502, 'mail_failed'); }
    }
    return { ok: true };   // نفس الجواب دائماً (ما نكشفوش واش الإيميل صحيح)
  }
  function adminCodeVerify(body) {
    const email = String(body.email || '').trim().toLowerCase().slice(0, 200), code = String(body.code || '').replace(/\D/g, '').slice(0, 6);
    const emailOk = crypto.timingSafeEqual(digest(email), digest(cfg.adminEmail || '-'));
    if (!adminCode.hash || Date.now() > adminCode.exp || adminCode.tries >= 5) { adminCode.hash = ''; throw httpErr(401, 'bad_credentials'); }
    adminCode.tries++;
    const ok = emailOk && code.length === 6 && crypto.timingSafeEqual(codeHash(code), Buffer.from(adminCode.hash, 'hex'));
    if (!ok) throw httpErr(401, 'bad_credentials');
    adminCode.hash = '';   // يُستعمل مرة وحدة
    return { ok: true, token: adminToken(), expiresInHours: cfg.adminSessionHours };
  }

  /* ---------- دخول الإدارة بالإيميل وكلمة المرور ---------- */
  const adminLoginEnabled = !!((cfg.adminEmail || cfg.adminPhone) && ((cfg.adminPasswordHash && /^scrypt\$[0-9a-f]+\$[0-9a-f]+$/.test(cfg.adminPasswordHash)) || cfg.adminPassword.length >= 12));
  function digest(v) { return crypto.createHash('sha256').update(String(v)).digest(); }
  function adminToken() {
    const exp = Date.now() + cfg.adminSessionHours * 3600000;
    return 'v1.' + exp + '.' + crypto.createHmac('sha256', cfg.secret).update('admin|' + exp).digest('base64url');
  }
  function adminTokenOk(tok) {
    const m = /^v1\.(\d{10,15})\.([A-Za-z0-9_\-]{43})$/.exec(String(tok || ''));
    if (!m || Number(m[1]) < Date.now()) return false;
    const want = Buffer.from(crypto.createHmac('sha256', cfg.secret).update('admin|' + m[1]).digest('base64url')), got = Buffer.from(m[2]);
    return want.length === got.length && crypto.timingSafeEqual(want, got);
  }
  function adminLogin(body) {
    if (!adminLoginEnabled) throw httpErr(503, 'admin_login_disabled');
    const email = String(body.email || '').trim().toLowerCase().slice(0, 200), pw = String(body.password || '').slice(0, 200);
    const emailOk = (!!cfg.adminEmail && crypto.timingSafeEqual(digest(email), digest(cfg.adminEmail))) || (!!cfg.adminPhone && normPhone(email) === cfg.adminPhone);
    let pwOk;
    if (cfg.adminPasswordHash) {
      const parts = cfg.adminPasswordHash.split('$');
      const got = crypto.scryptSync(pw, Buffer.from(parts[1], 'hex'), parts[2].length / 2);
      pwOk = crypto.timingSafeEqual(got, Buffer.from(parts[2], 'hex'));
    } else pwOk = crypto.timingSafeEqual(digest(pw), digest(cfg.adminPassword));
    if (!(emailOk && pwOk)) throw httpErr(401, 'bad_credentials');
    return { ok: true, token: adminToken(), expiresInHours: cfg.adminSessionHours };
  }
  function isAdmin(req) {
    if (adminTokenOk(req.headers['x-admin-token'])) return true;
    if (!cfg.adminKey) return false;
    const a = Buffer.from(String(req.headers['x-admin-key'] || '')), b = Buffer.from(cfg.adminKey);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  function readJson(req, max) {
    max = max || 4096;
    return new Promise(function (resolve, reject) {
      let n = 0, done = false; const chunks = [];
      req.on('data', function (c) {
        if (done) return;
        n += c.length;
        if (n > max) { done = true; reject(httpErr(413, 'too_large')); return; }
        chunks.push(c);
      });
      req.on('end', function () {
        if (done) return; done = true;
        try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
        catch (e) { reject(httpErr(400, 'bad_json')); }
      });
      req.on('error', function (e) { if (!done) { done = true; reject(e); } });
    });
  }

  function send(res, status, obj, extra) {
    const body = JSON.stringify(obj);
    res.writeHead(status, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }, extra || {}));
    res.end(body);
  }

  function checkIds(body, needAd) {
    const dev = String(body.device_id || '');
    if (!DEV_RE.test(dev)) throw httpErr(400, 'bad_device');
    let ad = '';
    if (needAd) { ad = String(body.ad_id || ''); if (!AD_RE.test(ad)) throw httpErr(400, 'bad_ad'); }
    return { ad: ad, dev: dev };
  }
  function userAgent(req) { return String(req.headers['user-agent'] || '').slice(0, 200); }
  function devKey(v) { const s = String(v || '').trim().toLowerCase(); if (!s || s.length > 40) throw httpErr(400, 'bad_dev'); return s; }

  /* ---------- المشاهدات ---------- */
  function recordView(req, body, ipHash) {
    const id = checkIds(body, true), ad = id.ad, dev = id.dev, day = today();
    if (q.validView.get(ad, dev, day)) return { ok: true, counted: false, reason: 'duplicate' };
    const ua = userAgent(req);
    let reason = null;
    if (!ua || BOT_RE.test(ua)) reason = 'bot_ua';
    else { const t = checkToken(body.token, ad, dev); if (t !== 'ok') reason = t; }
    if (!reason && q.ipDevices.get(ad, day, ipHash).n >= cfg.maxDevicesPerIpAdDay) reason = 'ip_many_devices';
    if (!reason && q.devAds.get(dev, day).n >= cfg.maxAdsPerDeviceDay) reason = 'device_flood';
    if (!reason && q.openAlert.get(ad)) reason = 'held';
    q.insertView.run(ad, dev, day, ipHash, ua, reason ? 0 : 1, reason, Date.now());
    const out = { ok: true, counted: !reason };
    if (reason && cfg.debug) out.reason = reason;
    return out;
  }

  function toggle(req, body, kind) {
    const id = checkIds(body, kind === 'like'), dev = id.dev;
    const ua = userAgent(req);
    if (!ua || BOT_RE.test(ua)) throw httpErr(403, 'bot');
    if (!q.hasActivity.get(dev)) throw httpErr(403, 'no_activity');   // لازم الجهاز يكون عنده مشاهدة صحيحة قبل اللايك/المتابعة
    if (kind === 'like') {
      const cur = !!q.likeGet.get(id.ad, dev);
      const on = typeof body.on === 'boolean' ? body.on : !cur;
      if (on && !cur) q.likeAdd.run(id.ad, dev, Date.now());
      if (!on && cur) q.likeDel.run(id.ad, dev);
      return { ok: true, liked: on, likes: q.likeCount.get(id.ad).n };
    }
    const dk = devKey(body.dev);
    const cur = !!q.followGet.get(dk, dev);
    const on = typeof body.on === 'boolean' ? body.on : !cur;
    if (on && !cur) q.followAdd.run(dk, dev, Date.now());
    if (!on && cur) q.followDel.run(dk, dev);
    return { ok: true, following: on, followers: q.followCount.get(dk).n };
  }

  /* ---------- الحسابات (رقم هاتف فريد + كلمة سر) ---------- */
  function scryptAsync(pw, salt) { return new Promise(function (res, rej) { crypto.scrypt(pw, salt, 64, function (e, k) { e ? rej(e) : res(k); }); }); }
  const DUMMY_SALT = crypto.randomBytes(16);
  function newSession(userId) {
    const token = crypto.randomBytes(32).toString('base64url'), now = Date.now();
    q.sessAdd.run(crypto.createHash('sha256').update(token).digest('hex'), userId, now, now + cfg.sessionDays * 86400000);
    q.sessTrim.run(userId, userId);
    return token;
  }
  function authUser(req) {
    const m = /^Bearer ([A-Za-z0-9_\-]{20,80})$/.exec(String(req.headers.authorization || ''));
    if (!m) return null;
    const now = Date.now(), u = q.sessGet.get(crypto.createHash('sha256').update(m[1]).digest('hex'), now) || null;
    if (u) { try { q.userSeen.run(now, u.id, now - 5 * 60000); } catch (e) { /* آخر ظهور: لا يوقف الطلب */ } }   // آخر ظهور (مرة كل 5 دقائق كحد أقصى)
    return u;
  }
  function isGooglePhone(ph) { return /^[gn]:/.test(String(ph || '')); }   // g: حساب Google، n: حساب اسم+كود
  function publicUser(u) { return { name: u.name, phone: isGooglePhone(u.phone) ? '' : u.phone, email: u.email || '', verified: !!u.verified }; }

  /* ---------- تأكيد الرقم برمز (SMS / واتساب عبر بوابتك) ---------- */
  const otpEnabled = !cfg.nameAuth && !!(cfg.otpSender || cfg.otpWebhookUrl || cfg.otpMode === 'console');
  function otpHash(phone, code) { return crypto.createHmac('sha256', cfg.secret).update('otp|' + phone + '|' + code).digest('hex'); }
  function countryOk(phone) { return cfg.otpCountries.some(function (c) { return phone.indexOf(c) === 0; }); }
  async function webhookSender(phone, code) {
    const message = 'رمز m1li: ' + code + ' (صالح 5 دقائق). لا تشاركه مع أحد.';
    const vals = { to: '+' + phone, phone: phone, code: code, message: message, channel: cfg.otpChannel };
    const form = cfg.otpWebhookType === 'form';
    let body;
    if (cfg.otpWebhookBody) body = cfg.otpWebhookBody.replace(/\{(to|phone|code|message|channel)\}/g, function (m, k) { return form ? encodeURIComponent(vals[k]) : JSON.stringify(vals[k]).slice(1, -1); });
    else body = form ? new URLSearchParams(vals).toString() : JSON.stringify(vals);
    const headers = { 'Content-Type': form ? 'application/x-www-form-urlencoded' : 'application/json' };
    if (cfg.otpWebhookAuth) headers['Authorization'] = cfg.otpWebhookAuth;
    const r = await fetch(cfg.otpWebhookUrl, { method: 'POST', headers: headers, body: body, signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error('webhook http ' + r.status);
  }
  async function consoleSender(phone, code) { console.log('🔑 OTP لـ +' + phone + ' : ' + code); }
  const otpDeliver = cfg.otpSender || (cfg.otpWebhookUrl ? webhookSender : consoleSender);

  async function otpSend(req, body, ipHash) {
    if (!otpEnabled) throw httpErr(404, 'otp_disabled');
    const phone = normPhone(body.phone);
    if (!phone) throw httpErr(400, 'bad_phone');
    if (!countryOk(phone)) throw httpErr(400, 'unsupported_country');
    const me = authUser(req), exist = q.userByPhone.get(phone);
    if (exist && !(me && me.phone === phone)) throw httpErr(409, 'phone_taken');
    if (exist && exist.verified) throw httpErr(409, 'already_verified');
    const now = Date.now(), row = q.otpGet.get(phone);
    if (row && now - row.last_sent < cfg.otpCooldownMs) throw httpErr(429, 'otp_cooldown');
    if (recent(otpPhoneTimes, phone, 3600000).length >= cfg.otpPerPhoneHour || recent(otpIpTimes, ipHash, 3600000).length >= cfg.otpPerIpHour) throw httpErr(429, 'rate_limited');
    const d = today(); if (otpDay.day !== d) otpDay = { day: d, n: 0 };
    if (otpDay.n >= cfg.otpDailyMax) throw httpErr(429, 'otp_daily_limit');
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    q.otpSet.run(phone, otpHash(phone, code), now + cfg.otpTtlMs, now);
    recent(otpPhoneTimes, phone, 3600000).push(now); recent(otpIpTimes, ipHash, 3600000).push(now); otpDay.n++;
    try { await otpDeliver(phone, code); }
    catch (e) { q.otpDel.run(phone); console.error('OTP send failed:', e && e.message); throw httpErr(502, 'send_failed'); }
    return { ok: true, cooldown: Math.round(cfg.otpCooldownMs / 1000), ttl: Math.round(cfg.otpTtlMs / 1000) };
  }
  function otpCheck(phone, code) {
    const row = q.otpGet.get(phone);
    if (!row || row.expires_at < Date.now()) throw httpErr(400, 'otp_expired');
    if (row.attempts >= cfg.otpMaxAttempts) { q.otpDel.run(phone); throw httpErr(429, 'otp_locked'); }
    const given = Buffer.from(otpHash(phone, String(code || '').replace(/\s/g, ''))), real = Buffer.from(row.code_hash);
    if (given.length !== real.length || !crypto.timingSafeEqual(given, real)) { q.otpAttempt.run(phone); throw httpErr(400, 'bad_code'); }
  }

  async function registerByName(body, ipHash) {
    const name = String(body.name || '').trim().replace(/\s+/g, ' ');
    if (name.length < 2 || name.length > 40) throw httpErr(400, 'bad_name');
    const pw = String(body.password || '');
    if (pw.length < 6 || pw.length > 72) throw httpErr(400, 'bad_password');
    if (RESERVED_NAME.test(name)) throw httpErr(409, 'name_taken');
    if (recent(regTimes, ipHash, 3600000).length >= cfg.registerPerIpHour) throw httpErr(429, 'rate_limited');
    if (q.nameTaken.get(name)) throw httpErr(409, 'name_taken');
    const salt = crypto.randomBytes(16), hash = await scryptAsync(pw, salt);
    let id;
    try { id = Number(q.userInsert.run('n:' + name.toLowerCase(), name, salt.toString('hex'), hash.toString('hex'), Date.now(), 1).lastInsertRowid); }
    catch (e) { if (/UNIQUE/i.test(String(e && e.message))) throw httpErr(409, 'name_taken'); throw e; }
    recent(regTimes, ipHash, 3600000).push(Date.now());
    return { ok: true, token: newSession(id), user: { name: name, phone: '', verified: true } };
  }
  async function loginByName(body, ipHash) {
    const name = String(body.name || '').trim().replace(/\s+/g, ' '), pw = String(body.password || '');
    if (!name || name.length > 40 || !pw || pw.length > 72) throw httpErr(401, 'bad_credentials');
    const kp = 'n:' + name.toLowerCase(), ki = 'i:' + ipHash;
    if (recent(loginFails, kp, 900000).length >= 5 || recent(loginFails, ki, 900000).length >= 30) throw httpErr(429, 'too_many_attempts');
    const u = q.userByName.get(name);
    const hash = await scryptAsync(pw, u ? Buffer.from(u.salt, 'hex') : DUMMY_SALT);
    const ok = !!u && crypto.timingSafeEqual(hash, Buffer.from(u.pass_hash, 'hex'));
    if (!ok) { recent(loginFails, kp, 900000).push(Date.now()); recent(loginFails, ki, 900000).push(Date.now()); throw httpErr(401, 'bad_credentials'); }
    loginFails.delete(kp);
    return { ok: true, token: newSession(u.id), user: publicUser(u) };
  }
  async function register(body, ipHash) {
    if (cfg.nameAuth) return registerByName(body, ipHash);
    const phone = normPhone(body.phone);
    if (!phone) throw httpErr(400, 'bad_phone');
    const name = String(body.name || '').trim().replace(/\s+/g, ' ');
    if (name.length < 2 || name.length > 40) throw httpErr(400, 'bad_name');
    const pw = String(body.password || '');
    if (pw.length < 8 || pw.length > 72) throw httpErr(400, 'bad_password');
    if (RESERVED_NAME.test(name)) throw httpErr(409, 'name_taken');
    if (recent(regTimes, ipHash, 3600000).length >= cfg.registerPerIpHour) throw httpErr(429, 'rate_limited');
    if (q.userByPhone.get(phone)) throw httpErr(409, 'phone_taken');
    if (q.nameTaken.get(name)) throw httpErr(409, 'name_taken');
    let verified = 0;
    if (otpEnabled) {
      if (!countryOk(phone)) throw httpErr(400, 'unsupported_country');
      if (!body.code) throw httpErr(400, 'otp_required');
      otpCheck(phone, body.code);
      verified = 1;
    }
    const salt = crypto.randomBytes(16), hash = await scryptAsync(pw, salt);
    let id;
    try { id = Number(q.userInsert.run(phone, name, salt.toString('hex'), hash.toString('hex'), Date.now(), verified).lastInsertRowid); }
    catch (e) { if (/UNIQUE/i.test(String(e && e.message))) throw httpErr(409, 'phone_taken'); throw e; }
    recent(regTimes, ipHash, 3600000).push(Date.now());
    q.otpDel.run(phone);
    return { ok: true, token: newSession(id), user: { name: name, phone: phone, verified: !!verified } };
  }

  async function login(body, ipHash) {
    if (cfg.nameAuth) return loginByName(body, ipHash);
    const phone = normPhone(body.phone), pw = String(body.password || '');
    if (!phone || !pw || pw.length > 72) throw httpErr(401, 'bad_credentials');
    const kp = 'p:' + phone, ki = 'i:' + ipHash;
    if (recent(loginFails, kp, 900000).length >= 5 || recent(loginFails, ki, 900000).length >= 30) throw httpErr(429, 'too_many_attempts');
    const u = q.userByPhone.get(phone);
    const hash = await scryptAsync(pw, u ? Buffer.from(u.salt, 'hex') : DUMMY_SALT);
    const ok = !!u && crypto.timingSafeEqual(hash, Buffer.from(u.pass_hash, 'hex'));
    if (!ok) { recent(loginFails, kp, 900000).push(Date.now()); recent(loginFails, ki, 900000).push(Date.now()); throw httpErr(401, 'bad_credentials'); }
    loginFails.delete(kp);
    return { ok: true, token: newSession(u.id), user: publicUser(u) };
  }

  /* ---------- تسجيل الدخول بـ Google ---------- */
  let jwksCache = { keys: null, at: 0 };
  async function googleKeys(force) {
    if (cfg.googleJwks) return cfg.googleJwks();
    if (!force && jwksCache.keys && Date.now() - jwksCache.at < 3600000) return jwksCache.keys;
    const r = await fetch('https://www.googleapis.com/oauth2/v3/certs', { signal: AbortSignal.timeout(6000) });
    if (!r.ok) throw new Error('jwks_http_' + r.status);
    const j = await r.json();
    jwksCache = { keys: Array.isArray(j.keys) ? j.keys : [], at: Date.now() };
    return jwksCache.keys;
  }
  /* يتحقق من توقيع RS256 + iss + aud + exp + email_verified، ويرجع بيانات الحساب */
  async function verifyGoogleToken(idToken) {
    const parts = String(idToken || '').split('.');
    if (parts.length !== 3 || String(idToken).length > 4096) throw httpErr(401, 'bad_google_token');
    let header, payload;
    try { header = JSON.parse(Buffer.from(parts[0], 'base64url').toString()); payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()); }
    catch (e) { throw httpErr(401, 'bad_google_token'); }
    if (header.alg !== 'RS256' || !header.kid) throw httpErr(401, 'bad_google_token');
    let keys;
    try {
      keys = await googleKeys(false);
      if (!keys.some(function (k) { return k.kid === header.kid; })) keys = await googleKeys(true);
    } catch (e) { console.error('google keys:', e && e.message); throw httpErr(503, 'google_unavailable'); }
    const jwk = keys.find(function (k) { return k.kid === header.kid; });
    if (!jwk) throw httpErr(401, 'bad_google_token');
    let okSig = false;
    try { okSig = crypto.verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url')); }
    catch (e) { okSig = false; }
    if (!okSig) throw httpErr(401, 'bad_google_token');
    if (payload.iss !== 'accounts.google.com' && payload.iss !== 'https://accounts.google.com') throw httpErr(401, 'bad_google_token');
    if (payload.aud !== cfg.googleClientId) throw httpErr(401, 'bad_google_token');
    if (!(Number(payload.exp) * 1000 > Date.now() - 30000)) throw httpErr(401, 'bad_google_token');
    if (!/^\d{5,30}$/.test(String(payload.sub || ''))) throw httpErr(401, 'bad_google_token');
    const email = String(payload.email || '').toLowerCase();
    if (!/^[^\s@]{1,64}@[^\s@]{1,255}$/.test(email) || email.length > 254) throw httpErr(401, 'bad_google_token');
    if (payload.email_verified !== true && payload.email_verified !== 'true') throw httpErr(403, 'email_unverified');
    return { sub: String(payload.sub), email: email, name: String(payload.name || '') };
  }
  function pickGoogleName(g) {
    let base = g.name.replace(/[\u0000-\u001f<>]/g, '').trim().replace(/\s+/g, ' ').slice(0, 36);
    if (base.length < 2) base = g.email.split('@')[0].replace(/[^\w.\-]/g, '').slice(0, 30);
    if (base.length < 2) base = 'user';
    for (let i = 0; i < 12; i++) {
      const cand = i === 0 ? base : base.slice(0, 34) + ' ' + (100 + crypto.randomInt(900));
      if (!RESERVED_NAME.test(cand) && !q.nameTaken.get(cand)) return cand;
    }
    return 'user ' + crypto.randomBytes(3).toString('hex');
  }
  async function googleLogin(body, ipHash) {
    if (!cfg.googleClientId) throw httpErr(503, 'google_unavailable');
    const ki = 'g:' + ipHash;
    if (recent(loginFails, ki, 900000).length >= 30) throw httpErr(429, 'too_many_attempts');
    let g;
    try { g = await verifyGoogleToken(body.credential); }
    catch (e) { if (e && e.status === 401) recent(loginFails, ki, 900000).push(Date.now()); throw e; }
    const exist = q.userByGoogle.get(g.sub);
    if (exist) return { ok: true, token: newSession(exist.id), user: publicUser(exist), created: false };
    if (recent(regTimes, ipHash, 3600000).length >= cfg.registerPerIpHour) throw httpErr(429, 'rate_limited');
    const name = pickGoogleName(g), salt = crypto.randomBytes(16), junk = crypto.randomBytes(64);   // لا كلمة سر: الدخول بـ Google فقط
    let id;
    try { id = Number(q.userInsertGoogle.run('g:' + g.sub, name, salt.toString('hex'), junk.toString('hex'), Date.now(), g.email, g.sub).lastInsertRowid); }
    catch (e) {
      if (/UNIQUE/i.test(String(e && e.message))) { const again = q.userByGoogle.get(g.sub); if (again) return { ok: true, token: newSession(again.id), user: publicUser(again), created: false }; throw httpErr(409, 'name_taken'); }
      throw e;
    }
    recent(regTimes, ipHash, 3600000).push(Date.now());
    return { ok: true, token: newSession(id), user: { name: name, phone: '', email: g.email, verified: true }, created: true };
  }

  /* ---------- التطبيقات (مرتبطة بحساب الناشر) ---------- */
  function str(v, max) { return String(v == null ? '' : v).trim().slice(0, max + 1); }
  function httpUrl(v) { try { const u = new URL(v); return u.protocol === 'http:' || u.protocol === 'https:'; } catch (e) { return false; } }
  const OWN_FILE_RE = /\/files\/(u(\d+)_[a-f0-9]{16}\.(apk|zip|jpg|png|webp|pdf))$/;
  function cleanApp(body, forceType) {
    const title = str(body.title, 60), desc = str(body.desc, 300), icon = str(body.icon, 500);
    const type = forceType || String(body.type || ''), category = String(body.category || '');
    const version = str(body.version, 12), bio = str(body.bio, 140);
    const url = str(body.url, 500), apkUrl = str(body.apkUrl, 500);
    const code = typeof body.code === 'string' ? body.code : '';
    if (!title || title.length > 60) throw httpErr(400, 'bad_title');
    if (!desc || desc.length > 300) throw httpErr(400, 'bad_desc');
    if (!icon || (httpUrl(icon) ? icon.length > 500 : icon.length > 16)) throw httpErr(400, 'bad_icon');
    if (APP_CATS.indexOf(category) === -1) throw httpErr(400, 'bad_category');
    if (['code', 'url', 'apk'].indexOf(type) === -1) throw httpErr(400, 'bad_type');
    if (version.length > 12 || bio.length > 140) throw httpErr(400, 'bad_field');
    if (apkUrl && (!httpUrl(apkUrl) || apkUrl.length > 500)) throw httpErr(400, 'bad_apk');
    if (type === 'apk' && !apkUrl) throw httpErr(400, 'bad_apk');
    if (type === 'url' && (!httpUrl(url) || url.length > 500)) throw httpErr(400, 'bad_url');
    if (type === 'code' && (!code.trim() || code.length > 500000)) throw httpErr(400, 'bad_code');
    return { title: title, desc: desc, icon: icon, type: type, category: category, version: version, bio: bio, url: url, apkUrl: apkUrl, code: code };
  }
  function checkPublisher(user) {
    if (cfg.publishRequireGoogle && !user.email) throw httpErr(403, 'google_required');
    if (otpEnabled && !user.verified) throw httpErr(403, 'phone_unverified');
  }
  /* حذف ملف مرفوع من السيرفر (فقط إذا كان يخص نفس المستخدم) */
  function dropFile(ownerId, fileUrl) {
    const m = OWN_FILE_RE.exec(String(fileUrl || '').split('?')[0]);
    if (!m || Number(m[2]) !== Number(ownerId)) return;
    fs.unlink(path.join(cfg.uploadDir, m[1]), function () {});
  }
  function publishApp(user, body) {
    const f = cleanApp(body);
    checkPublisher(user);
    if (q.appCount.get(user.id).n >= cfg.maxAppsPerUser) throw httpErr(409, 'too_many_apps');
    if (recent(pubTimes, user.id, 3600000).length >= cfg.publishPerHour) throw httpErr(429, 'rate_limited');
    const id = 'a_' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
    const now = Date.now(), publishAt = cfg.publishDelayMin > 0 ? now + cfg.publishDelayMin * 60000 : 0;
    db.exec('BEGIN');
    try {
      q.appInsert.run(id, user.id, f.title, f.category, f.desc, f.icon, f.type, f.type === 'code' ? f.code : '', f.type === 'url' ? f.url : '', f.apkUrl, f.version, now, publishAt, now);
      if (f.bio) q.bioSet.run(f.bio, user.id);
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    recent(pubTimes, user.id, 3600000).push(Date.now());
    return { ok: true, id: id, publishAt: publishAt, live: publishAt === 0 };
  }
  function updateApp(user, id, body) {
    const row = q.appGet.get(id);
    if (!row) throw httpErr(404, 'not_found');
    if (row.user_id !== user.id) throw httpErr(403, 'forbidden');
    checkPublisher(user);
    if (recent(updTimes, user.id, 3600000).length >= cfg.updatePerHour) throw httpErr(429, 'rate_limited');
    const f = cleanApp(body, row.type);   // نوع التطبيق ثابت، والباقي قابل للتعديل
    q.appUpdate.run(f.title, f.category, f.desc, f.icon, f.type === 'code' ? f.code : '', f.type === 'url' ? f.url : '', f.apkUrl, f.version, Date.now(), id, user.id);
    if (f.bio) q.bioSet.run(f.bio, user.id);
    if (row.apk_url && row.apk_url !== f.apkUrl) dropFile(user.id, row.apk_url);   // الملف القديم ما بقاش مستعمل
    recent(updTimes, user.id, 3600000).push(Date.now());
    return { ok: true, id: id };
  }
  /* ---------- رفع الملفات: ZIP / APK / صور / PDF (ثنائي خام) ---------- */
  const UP_KINDS = {
    zip: { max: function () { return cfg.maxUploadMb * 1024 * 1024; }, magic: function (h) { return h[0] === 0x50 && h[1] === 0x4b && h[2] === 3 && h[3] === 4; }, err: 'not_zip' },
    apk: { max: function () { return cfg.maxUploadMb * 1024 * 1024; }, magic: function (h) { return h[0] === 0x50 && h[1] === 0x4b && h[2] === 3 && h[3] === 4; }, err: 'not_zip' },
    jpg: { max: function () { return cfg.maxImageMb * 1024 * 1024; }, magic: function (h) { return h[0] === 0xff && h[1] === 0xd8 && h[2] === 0xff; }, err: 'not_image' },
    png: { max: function () { return cfg.maxImageMb * 1024 * 1024; }, magic: function (h) { return h[0] === 0x89 && h[1] === 0x50 && h[2] === 0x4e && h[3] === 0x47; }, err: 'not_image' },
    webp: { max: function () { return cfg.maxImageMb * 1024 * 1024; }, magic: function (h) { return h.slice(0, 4).toString() === 'RIFF' && h.slice(8, 12).toString() === 'WEBP'; }, err: 'not_image' },
    pdf: { max: function () { return cfg.maxPdfMb * 1024 * 1024; }, magic: function (h) { return h.slice(0, 4).toString() === '%PDF'; }, err: 'not_pdf' }
  };
  function receiveUpload(req, res, user, nameParam) {
    return new Promise(function (resolve, reject) {
      let ext = (/\.(apk|zip|jpe?g|png|webp|pdf)$/i.exec(String(nameParam || '')) || [])[1];
      if (!ext) return reject(httpErr(400, 'bad_file_type'));
      ext = ext.toLowerCase(); if (ext === 'jpeg') ext = 'jpg';
      const kind = UP_KINDS[ext];
      checkPublisher(user);
      if (recent(upTimes, user.id, 3600000).length >= cfg.uploadsPerHour) return reject(httpErr(429, 'rate_limited'));
      const max = kind.max(), len = Number(req.headers['content-length'] || 0);
      if (!len) return reject(httpErr(411, 'length_required'));
      if (len > max) return reject(httpErr(413, 'too_large'));
      fs.mkdirSync(cfg.uploadDir, { recursive: true });
      const fname = 'u' + user.id + '_' + crypto.randomBytes(8).toString('hex') + '.' + ext;
      const tmp = path.join(cfg.uploadDir, fname + '.part'), out = fs.createWriteStream(tmp);
      let n = 0, head = Buffer.alloc(0), failed = false;
      function fail(err) { if (failed) return; failed = true; try { out.destroy(); } catch (e) {} fs.unlink(tmp, function () {}); reject(err); }
      req.on('data', function (c) {
        if (failed) return;
        n += c.length;
        if (n > max) { req.unpipe(out); return fail(httpErr(413, 'too_large')); }
        if (head.length < 12) head = Buffer.concat([head, c]).slice(0, 12);
      });
      req.on('error', fail);
      out.on('error', fail);
      out.on('finish', function () {
        if (failed) return;
        if (n < 12 || !kind.magic(head)) return fail(httpErr(400, kind.err));
        if ((ext === 'zip' || ext === 'apk') && n < 22) return fail(httpErr(400, 'not_zip'));
        fs.rename(tmp, path.join(cfg.uploadDir, fname), function (er) {
          if (er) return fail(er);
          recent(upTimes, user.id, 3600000).push(Date.now());
          resolve({ ok: true, url: publicBase(req) + '/files/' + fname, size: n });
        });
      });
      req.pipe(out);
    });
  }
  function publicBase(req) {
    const proto = cfg.trustProxy && req.headers['x-forwarded-proto'] ? String(req.headers['x-forwarded-proto']).split(',')[0].trim() : 'http';
    return cfg.publicUrl || (proto + '://' + String(req.headers.host || 'localhost'));
  }
  const FILE_MIME = { apk: 'application/vnd.android.package-archive', zip: 'application/zip', jpg: 'image/jpeg', png: 'image/png', webp: 'image/webp', pdf: 'application/pdf' };
  function serveFile(req, res, p) {
    const m = /^\/files\/(u\d+_[a-f0-9]{16}\.(apk|zip|jpg|png|webp|pdf))$/.exec(p);
    if (!m || (req.method !== 'GET' && req.method !== 'HEAD')) { res.writeHead(404); return res.end('Not found'); }
    const full = path.join(cfg.uploadDir, m[1]);
    fs.stat(full, function (err, st) {
      if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
      const ext = m[2], inline = ext === 'jpg' || ext === 'png' || ext === 'webp' || ext === 'pdf';
      const h = { 'Content-Type': FILE_MIME[ext], 'Content-Length': st.size, 'X-Content-Type-Options': 'nosniff', 'Access-Control-Allow-Origin': '*', 'Cross-Origin-Resource-Policy': 'cross-origin' };
      if (inline) { h['Cache-Control'] = 'public, max-age=604800'; h['Content-Security-Policy'] = "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'"; if (ext === 'pdf') { h['Content-Security-Policy'] = 'sandbox'; h['Content-Disposition'] = 'inline; filename="' + m[1] + '"'; } }
      else h['Content-Disposition'] = 'attachment; filename="' + m[1] + '"';
      res.writeHead(200, h);
      if (req.method === 'HEAD') return res.end();
      fs.createReadStream(full).pipe(res);
    });
  }
  function ownUpload(url, userId, exts) {   // رابط ملف مرفوع يخص هذا المستخدم وموجود فعلاً على القرص؟ -> اسم الملف أو ''
    const m = OWN_FILE_RE.exec(String(url || '').split('?')[0]);
    if (!m || Number(m[2]) !== Number(userId) || exts.indexOf(m[3]) === -1) return '';
    return fs.existsSync(path.join(cfg.uploadDir, m[1])) ? m[1] : '';
  }

  /* ---------- الفحص الآلي لملف ZIP (بدون مكتبات) + الاستخراج الآمن للتشغيل ---------- */
  const ZIP_LIMITS = { entries: 3000, total: 250 * 1024 * 1024, file: 60 * 1024 * 1024 };
  const DANGER_EXT = /\.(exe|dll|bat|cmd|com|msi|scr|ps1|vbs|vbe|wsf|sh|bash|php\d?|phtml|jsp|asp|aspx|cgi|pl|py|rb|jar|so|dylib|lnk|reg|hta)$/i;
  const WEB_EXT = /\.(html?|css|js|mjs|json|txt|md|xml|webmanifest|map|wasm|png|jpe?g|gif|webp|avif|svg|ico|bmp|mp3|ogg|wav|m4a|mp4|webm|woff2?|ttf|otf|glb|gltf|bin|atlas|csv|tsv)$/i;
  const PLAY_MIME = { '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8', '.xml': 'application/xml; charset=utf-8', '.webmanifest': 'application/manifest+json',
    '.map': 'application/json', '.wasm': 'application/wasm', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.avif': 'image/avif',
    '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.bmp': 'image/bmp', '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg', '.wav': 'audio/wav', '.m4a': 'audio/mp4', '.mp4': 'video/mp4', '.webm': 'video/webm',
    '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.otf': 'font/otf', '.glb': 'model/gltf-binary', '.gltf': 'model/gltf+json', '.csv': 'text/csv; charset=utf-8', '.tsv': 'text/tab-separated-values; charset=utf-8' };
  const STORAGE_SHIM = '<script>(function(){try{window.localStorage.getItem("x")}catch(e){var m={},s={getItem:function(k){return k in m?m[k]:null},setItem:function(k,v){m[k]=String(v)},removeItem:function(k){delete m[k]},clear:function(){m={}},key:function(i){return Object.keys(m)[i]||null}};Object.defineProperty(s,"length",{get:function(){return Object.keys(m).length}});["localStorage","sessionStorage"].forEach(function(n){try{Object.defineProperty(window,n,{value:s,configurable:true})}catch(x){}})}})();</script>';

  function readZipDirectory(buf) {
    let e = -1;
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) { if (buf.readUInt32LE(i) === 0x06054b50) { e = i; break; } }
    if (e < 0) throw httpErr(400, 'not_zip');
    const count = buf.readUInt16LE(e + 10), cdSize = buf.readUInt32LE(e + 12), cdOff = buf.readUInt32LE(e + 16);
    if (count === 0xffff || cdOff === 0xffffffff || cdOff + cdSize > buf.length) throw httpErr(400, 'zip_unsupported');
    if (count > ZIP_LIMITS.entries) throw httpErr(400, 'zip_too_many_files');
    const list = []; let o = cdOff;
    for (let i = 0; i < count; i++) {
      if (o + 46 > buf.length || buf.readUInt32LE(o) !== 0x02014b50) throw httpErr(400, 'not_zip');
      const flags = buf.readUInt16LE(o + 8), method = buf.readUInt16LE(o + 10), csize = buf.readUInt32LE(o + 20), usize = buf.readUInt32LE(o + 24);
      const nl = buf.readUInt16LE(o + 28), el = buf.readUInt16LE(o + 30), cl = buf.readUInt16LE(o + 32), lho = buf.readUInt32LE(o + 42);
      const name = buf.toString('utf8', o + 46, o + 46 + nl);
      list.push({ name: name, flags: flags, method: method, csize: csize, usize: usize, off: lho });
      o += 46 + nl + el + cl;
    }
    return list;
  }
  function zipEntryData(buf, en) {
    if (en.flags & 1) throw httpErr(400, 'zip_encrypted');
    const o = en.off;
    if (o + 30 > buf.length || buf.readUInt32LE(o) !== 0x04034b50) throw httpErr(400, 'not_zip');
    const start = o + 30 + buf.readUInt16LE(o + 26) + buf.readUInt16LE(o + 28);
    const raw = buf.subarray(start, start + en.csize);
    if (en.method === 0) return Buffer.from(raw);
    if (en.method !== 8) throw httpErr(400, 'zip_unsupported');
    const out = zlib.inflateRawSync(raw, { maxOutputLength: en.usize + 1 });
    if (out.length !== en.usize) throw httpErr(400, 'not_zip');
    return out;
  }
  function cleanZipName(n) {
    n = String(n).replace(/\\/g, '/').replace(/^(\.\/)+/, '');
    if (!n || n.indexOf('\0') !== -1 || n.charAt(0) === '/' || /^[A-Za-z]:/.test(n)) return null;
    const parts = n.split('/');
    if (parts.some(function (s) { return s === '..'; })) return null;
    return parts.filter(function (s) { return s !== '.'; }).join('/');
  }
  /* يرجع { report, files:[{name,en}] } — files هي ملفات الويب الصالحة للاستخراج بعد إزالة المجلد الجذر المشترك */
  function analyzeZip(buf, uploadedExt) {
    const R = { kind: 'other', entry: '', fileCount: 0, totalBytes: 0, title: '', issues: [], notes: [], verdict: 'rejected' };
    const issue = function (level, msg) { R.issues.push({ level: level, msg: msg }); };
    const dir = readZipDirectory(buf);
    let entries = [];
    dir.forEach(function (en) {
      if (/\/$/.test(en.name)) return;
      const nm = cleanZipName(en.name);
      if (nm === null) { issue('high', 'مسار ملف مشبوه داخل الأرشيف (' + en.name.slice(0, 60) + ')'); return; }
      if (/^__MACOSX\//.test(nm) || /(^|\/)(\.DS_Store|Thumbs\.db)$/.test(nm)) return;
      entries.push({ name: nm, en: en });
    });
    R.fileCount = entries.length;
    R.totalBytes = entries.reduce(function (s, x) { return s + x.en.usize; }, 0);
    if (!entries.length) issue('high', 'الملف فارغ.');
    if (R.totalBytes > ZIP_LIMITS.total) issue('high', 'حجم الملفات بعد فك الضغط كبير جداً (الحد 250MB).');
    if (entries.some(function (x) { return x.en.usize > ZIP_LIMITS.file; })) issue('high', 'يوجد ملف واحد أكبر من 60MB.');
    if (buf.length > 0 && R.totalBytes / buf.length > 200 && R.totalBytes > 50 * 1024 * 1024) issue('high', 'نسبة الضغط غير طبيعية (قنبلة ضغط محتملة).');
    if (entries.some(function (x) { return x.en.flags & 1; })) issue('high', 'الأرشيف محمي بكلمة سر ولا يمكن فحصه.');
    if (R.issues.some(function (i) { return i.level === 'high'; })) return { report: R };

    const names = entries.map(function (x) { return x.name; });
    const isApk = names.indexOf('AndroidManifest.xml') !== -1 && names.some(function (n) { return /^classes\d*\.dex$/.test(n); });
    const innerApk = names.filter(function (n) { return /\.(apk|aab)$/i.test(n); });
    if (isApk || uploadedExt === 'apk') { R.kind = 'android'; R.notes.push('ملف تطبيق أندرويد (APK): يُنشر للتحميل فقط، ولا يعمل داخل المتصفح.'); R.verdict = 'download'; return { report: R }; }
    if (innerApk.length) { R.kind = 'android'; R.notes.push('الأرشيف يحوي ملف APK: يُنشر للتحميل فقط.'); R.verdict = 'download'; return { report: R }; }

    // إزالة المجلد الجذر المشترك (مثل my-game/index.html)
    const tops = {}; names.forEach(function (n) { tops[n.indexOf('/') === -1 ? '' : n.split('/')[0]] = 1; });
    let prefix = '';
    const topKeys = Object.keys(tops);
    if (topKeys.length === 1 && topKeys[0] !== '') prefix = topKeys[0] + '/';
    const files = entries.map(function (x) { return { name: prefix ? x.name.slice(prefix.length) : x.name, en: x.en }; });

    const danger = files.filter(function (f) { return DANGER_EXT.test(f.name); });
    if (danger.length) issue('high', 'ملفات تنفيذية/سيرفر غير مسموحة: ' + danger.slice(0, 4).map(function (f) { return f.name; }).join('، '));
    const isGradle = files.some(function (f) { return /(^|\/)(build\.gradle(\.kts)?|settings\.gradle)$/.test(f.name); });
    const htmls = files.filter(function (f) { return /\.html?$/i.test(f.name); });
    let entry = files.some(function (f) { return f.name === 'index.html'; }) ? 'index.html' : '';
    if (!entry) { const rootHtml = htmls.filter(function (f) { return f.name.indexOf('/') === -1; }); if (rootHtml.length === 1) entry = rootHtml[0].name; }
    if (!entry && htmls.length === 1) entry = htmls[0].name;
    if (!entry) {
      R.kind = isGradle ? 'android-src' : 'other';
      issue('medium', isGradle ? 'هذا مشروع أندرويد (مصدر) وليس تطبيقاً مبنياً. ابنِ ملف APK ثم ارفعه.' : 'لم أجد ملف index.html في الأرشيف، لذلك لا يمكن تشغيله في المتصفح.');
      R.verdict = R.issues.some(function (i) { return i.level === 'high'; }) ? 'rejected' : 'download';
      return { report: R };
    }
    R.kind = 'web'; R.entry = entry;

    // فحص الشيفرة (أنماط بسيطة، ليس مراجعة بشرية)
    let skipped = 0; const scanned = [];
    files.forEach(function (f) {
      if (!WEB_EXT.test(f.name)) { skipped++; return; }
      scanned.push(f);
    });
    if (skipped) issue('low', 'تم تجاهل ' + skipped + ' ملف بصيغ غير مدعومة للتشغيل.');
    const PAT = [
      { re: /coinhive|cryptonight|minero|webminer|coin-hive/i, level: 'high', msg: 'كود يشبه تعدين العملات الرقمية.' },
      { re: /document\.cookie/i, level: 'medium', msg: 'يقرأ/يكتب document.cookie.' },
      { re: /\beval\s*\(|new\s+Function\s*\(/i, level: 'low', msg: 'يستعمل eval/new Function.' },
      { re: /window\.top|top\.location|parent\.location/i, level: 'medium', msg: 'يحاول الوصول للنافذة الأم/تغيير العنوان.' },
      { re: /<script[^>]+src=["']https?:\/\/(?!cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|ajax\.googleapis\.com|code\.jquery\.com|fonts\.googleapis\.com|cdn\.tailwindcss\.com)/i, level: 'low', msg: 'يحمّل سكربتات من مواقع خارجية.' }
    ];
    const seen = {};
    scanned.forEach(function (f) {
      if (!/\.(html?|js|mjs)$/i.test(f.name) || f.en.usize > 2 * 1024 * 1024) return;
      let txt = ''; try { txt = zipEntryData(buf, f.en).toString('utf8'); } catch (e) { return; }
      PAT.forEach(function (p) { if (!seen[p.msg] && p.re.test(txt)) { seen[p.msg] = 1; issue(p.level, p.msg + ' (' + f.name.slice(0, 40) + ')'); } });
      if (f.name === entry) { const t = /<title[^>]*>([^<]{1,80})<\/title>/i.exec(txt); if (t) R.title = t[1].trim(); }
    });
    R.fileCount = scanned.length;
    R.verdict = R.issues.some(function (i) { return i.level === 'high'; }) ? 'rejected' : (R.issues.some(function (i) { return i.level === 'medium'; }) ? 'review' : 'ok');
    return { report: R, files: scanned };
  }
  function extractWebApp(buf, files, appId) {
    const root = path.join(cfg.appsDir, appId);
    fs.rmSync(root, { recursive: true, force: true });
    fs.mkdirSync(root, { recursive: true });
    let total = 0;
    files.forEach(function (f) {
      const dest = path.resolve(root, f.name);
      if (path.relative(root, dest).indexOf('..') === 0 || path.isAbsolute(path.relative(root, dest))) return;
      let data = zipEntryData(buf, f.en);
      total += data.length; if (total > ZIP_LIMITS.total) throw httpErr(400, 'zip_too_large');
      if (/\.html?$/i.test(f.name)) {
        let s = data.toString('utf8');
        s = /<head[^>]*>/i.test(s) ? s.replace(/<head[^>]*>/i, function (m) { return m + STORAGE_SHIM; }) : STORAGE_SHIM + s;
        data = Buffer.from(s, 'utf8');
      }
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, data);
    });
  }
  function dropPlayDir(id) { if (/^a_[a-z0-9]{3,40}$/.test(id)) fs.rm(path.join(cfg.appsDir, id), { recursive: true, force: true }, function () {}); }
  /* التطبيقات المستخرجة تُقدَّم من /play/<id>/… داخل «sandbox» (أصل معزول: لا وصول لجلسة المستخدم) */
  function servePlay(req, res, p) {
    const m = /^\/play\/(a_[a-z0-9]{3,40})\/(.*)$/.exec(p);
    if (!m || (req.method !== 'GET' && req.method !== 'HEAD')) { res.writeHead(404); return res.end('Not found'); }
    const row = q.appOwn.get(m[1]);
    if (!row) { res.writeHead(404); return res.end('Not found'); }
    let rel; try { rel = decodeURIComponent(m[2]); } catch (e) { res.writeHead(400); return res.end(); }
    if (!rel || rel.slice(-1) === '/') rel += 'index.html';
    const root = path.join(cfg.appsDir, m[1]), full = path.resolve(root, rel);
    const r = path.relative(root, full);
    if (rel.indexOf('\0') !== -1 || !r || r.indexOf('..') === 0 || path.isAbsolute(r)) { res.writeHead(404); return res.end('Not found'); }
    fs.stat(full, function (err, st) {
      if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': PLAY_MIME[path.extname(full).toLowerCase()] || 'application/octet-stream', 'Content-Length': st.size, 'Cache-Control': 'public, max-age=300',
        'X-Content-Type-Options': 'nosniff', 'Access-Control-Allow-Origin': '*', 'Cross-Origin-Resource-Policy': 'cross-origin', 'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': 'sandbox allow-scripts allow-forms allow-modals allow-popups allow-pointer-lock' });
      if (req.method === 'HEAD') return res.end();
      fs.createReadStream(full).pipe(res);
    });
  }

  /* ---------- «النشر الآلي»: فحص ZIP ثم نشره وتشغيله ---------- */
  const CAT_EMOJI = { games: '🎮', tools: '🧰', productivity: '📈', lifestyle: '✨' };
  function ownImages(arr, userId, max) {
    if (!Array.isArray(arr)) return [];
    return arr.slice(0, max).filter(function (u) { return typeof u === 'string' && u.length <= 500 && ownUpload(u, userId, ['jpg', 'png', 'webp']); });
  }
  function publishAppAuto(req, user, body) {
    body = body || {};
    const title = str(body.title, 60), category = String(body.category || 'tools'), version = str(body.version, 12);
    if (!title) throw httpErr(400, 'bad_title');
    if (APP_CATS.indexOf(category) === -1) throw httpErr(400, 'bad_category');
    const desc = str(body.desc, 300) || (title + ' — تطبيق منشور على m1li');
    checkPublisher(user);
    if (q.appCount.get(user.id).n >= cfg.maxAppsPerUser) throw httpErr(409, 'too_many_apps');
    if (recent(pubTimes, user.id, 3600000).length >= cfg.publishPerHour) throw httpErr(429, 'rate_limited');
    const zipUrl = String(body.zipUrl || '').split('?')[0];
    const zipName = ownUpload(zipUrl, user.id, ['zip', 'apk']);
    if (!zipName) throw httpErr(400, 'bad_apk');
    const images = ownImages(body.images, user.id, 6);
    const icon = images[0] || CAT_EMOJI[category];
    const buf = fs.readFileSync(path.join(cfg.uploadDir, zipName));
    let a;
    try { a = analyzeZip(buf, zipName.slice(-3)); }
    catch (e) { if (e && e.status) { e.report = { kind: 'other', issues: [{ level: 'high', msg: 'تعذّر قراءة الملف (' + e.code + ').' }], notes: [], verdict: 'rejected' }; } throw e; }
    const rep = a.report;
    if (rep.verdict === 'rejected') { const er = httpErr(422, 'zip_rejected'); er.report = rep; throw er; }
    const id = 'a_' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
    const now = Date.now();
    let type, url = '', apkUrl = '';
    if (rep.kind === 'web') {
      extractWebApp(buf, a.files, id);
      type = 'url'; url = publicBase(req) + '/play/' + id + '/' + rep.entry.split('/').map(encodeURIComponent).join('/');
    } else { type = 'apk'; apkUrl = zipUrl; }
    const auto = cfg.autoPublish && rep.kind === 'web' && rep.verdict === 'ok';
    const publishAt = auto || cfg.publishDelayMin <= 0 ? 0 : now + cfg.publishDelayMin * 60000;
    db.exec('BEGIN');
    try {
      q.appInsert.run(id, user.id, title, category, desc, icon, type, '', url, apkUrl, version, now, publishAt, now);
      q.appExtra.run(JSON.stringify(images), JSON.stringify(rep), id);
      if (str(body.bio, 140)) q.bioSet.run(str(body.bio, 140), user.id);
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); if (rep.kind === 'web') dropPlayDir(id); throw e; }
    if (rep.kind === 'web') dropFile(user.id, zipUrl);   // الملفات صارت مستخرجة؛ لا حاجة للأرشيف
    recent(pubTimes, user.id, 3600000).push(Date.now());
    notifyNewApp(user, { title: title, type: type, category: category, desc: desc, url: url, apkUrl: apkUrl }, id);
    return { ok: true, id: id, publishAt: publishAt, live: publishAt === 0, kind: rep.kind, report: rep };
  }

  /* ---------- المنتجات والكتب (من المستخدمين) ---------- */
  const listQ = {
    insert: db.prepare('INSERT INTO listings (id,user_id,kind,title,desc,price,city,whatsapp,images,file_url,extra,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'),
    byKind: db.prepare("SELECT l.*, u.name AS seller FROM listings l JOIN users u ON u.id=l.user_id WHERE l.status='active' AND l.kind=? ORDER BY l.created_at DESC LIMIT 300"),
    get: db.prepare("SELECT * FROM listings WHERE id=? AND status='active'"),
    del: db.prepare('DELETE FROM listings WHERE id=?'),
    count: db.prepare("SELECT COUNT(*) AS n FROM listings WHERE user_id=? AND status='active'"),
    remove: db.prepare("UPDATE listings SET status='removed' WHERE id=? AND status='active'"),
    adminList: db.prepare('SELECT l.id,l.kind,l.title,l.price,l.city,l.whatsapp,l.status,l.created_at,u.name,u.phone,u.email FROM listings l JOIN users u ON u.id=l.user_id ORDER BY l.created_at DESC LIMIT 300')
  };
  const listTimes = new Map();
  function listingPublic(r, me) {
    let images = []; try { images = JSON.parse(r.images); } catch (e) {}
    return { id: r.id, kind: r.kind, title: r.title, desc: r.desc, price: r.price, city: r.city, whatsapp: r.kind === 'product' ? r.whatsapp : '', images: images,
      fileUrl: r.kind === 'book' ? r.file_url : '', author: r.kind === 'book' ? r.extra : '', seller: r.seller || '', created: r.created_at, mine: !!(me && me.id === r.user_id) };
  }
  function publishListing(user, body) {
    body = body || {};
    const kind = body.kind === 'book' ? 'book' : body.kind === 'product' ? 'product' : '';
    if (!kind) throw httpErr(400, 'bad_kind');
    checkPublisher(user);
    if (listQ.count.get(user.id).n >= cfg.maxListingsPerUser) throw httpErr(409, 'too_many_listings');
    if (recent(listTimes, user.id, 3600000).length >= cfg.listingsPerHour) throw httpErr(429, 'rate_limited');
    const title = str(body.title, 100), desc = str(body.desc, 600);
    if (title.length < 2) throw httpErr(400, 'bad_title');
    const images = ownImages(body.images, user.id, kind === 'book' ? 1 : 4);
    if (!images.length) throw httpErr(400, 'bad_image');
    let price = 0, city = '', whatsapp = '', fileUrl = '', extra = '';
    if (kind === 'product') {
      price = Number(body.price);
      if (!Number.isFinite(price) || price <= 0 || price > 1e6) throw httpErr(400, 'bad_price');
      price = Math.round(price * 100) / 100;
      city = str(body.city, 40); if (city.length < 2) throw httpErr(400, 'bad_city');
      whatsapp = normPhone(body.whatsapp); if (!whatsapp) throw httpErr(400, 'bad_whatsapp');
    } else {
      const f = ownUpload(String(body.fileUrl || '').split('?')[0], user.id, ['pdf']);
      if (!f) throw httpErr(400, 'bad_file');
      fileUrl = String(body.fileUrl).split('?')[0];
      extra = str(body.author, 60);
    }
    const id = (kind === 'book' ? 'k_' : 'l_') + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
    listQ.insert.run(id, user.id, kind, title, desc, price, city, whatsapp, JSON.stringify(images), fileUrl, extra, Date.now());
    recent(listTimes, user.id, 3600000).push(Date.now());
    return { ok: true, id: id };
  }
  function deleteListing(user, id) {
    const r = listQ.get.get(id);
    if (!r) throw httpErr(404, 'not_found');
    if (r.user_id !== user.id) throw httpErr(403, 'forbidden');
    try { JSON.parse(r.images).forEach(function (u) { dropFile(user.id, u); }); } catch (e) {}
    if (r.file_url) dropFile(user.id, r.file_url);
    listQ.del.run(id);
    return { ok: true };
  }

  function parseImgs(v) { try { const a = JSON.parse(v || '[]'); return Array.isArray(a) ? a : []; } catch (e) { return []; } }
  function appPublic(r, me) {
    return { id: r.id, title: r.title, category: r.category, desc: r.desc, icon: r.icon, type: r.type, url: r.url || '', apkUrl: r.apk_url || '', version: r.version || '', developer: r.developer, bio: r.bio || '', created: r.created_at, updated: r.updated_at || 0, live: !r.publish_at || r.publish_at <= Date.now(), publishAt: r.publish_at || 0, hasCode: !!r.has_code, images: parseImgs(r.images), mine: !!(me && me.id === r.user_id) };
  }

  function stats(url) {
    const raw = String(url.searchParams.get('ids') || '').split(',');
    const ids = []; raw.forEach(function (s) { if (AD_RE.test(s) && ids.indexOf(s) === -1 && ids.length < 100) ids.push(s); });
    const out = {}; ids.forEach(function (i) { out[i] = { views: 0, likes: 0 }; });
    let liked = [];
    if (ids.length) {
      const ph = ids.map(function () { return '?'; }).join(',');
      const vq = db.prepare('SELECT ad_id, COUNT(*) AS n FROM views WHERE valid=1 AND ad_id IN (' + ph + ') GROUP BY ad_id');
      vq.all.apply(vq, ids).forEach(function (r) { out[r.ad_id].views = r.n; });
      const lq = db.prepare('SELECT ad_id, COUNT(*) AS n FROM likes WHERE ad_id IN (' + ph + ') GROUP BY ad_id');
      lq.all.apply(lq, ids).forEach(function (r) { out[r.ad_id].likes = r.n; });
      const d = String(url.searchParams.get('d') || '');
      if (DEV_RE.test(d)) {
        const mq = db.prepare('SELECT ad_id FROM likes WHERE device_id=? AND ad_id IN (' + ph + ')');
        liked = mq.all.apply(mq, [d].concat(ids)).map(function (r) { return r.ad_id; });
      }
    }
    return { ok: true, stats: out, liked: liked };
  }

  /* ---------- كشف الشذوذ (إحصائي) ---------- */
  function detect(now) {
    now = now || Date.now();
    const W = cfg.anomalyWindowMs, H = 24 * 3600 * 1000, nb = Math.floor(H / W), start = now - W;
    let flagged = 0;
    q.recentAds.all(start).forEach(function (r) {
      if (q.openAlert.get(r.ad_id)) return;
      let kind = null, detail = null;
      if (r.n >= cfg.ipConcentrationMin) {
        const top = q.topIp.get(r.ad_id, start);
        if (top && top.n / r.n > cfg.ipConcentration) { kind = 'ip_concentration'; detail = JSON.stringify({ views: r.n, topIpShare: Math.round(top.n / r.n * 100) / 100 }); }
      }
      if (!kind && r.n >= cfg.anomalyMinViews) {
        let sum = 0, sq = 0;
        q.buckets.all(start - 1, W, r.ad_id, start - H, start).forEach(function (b) {
          if (b.b >= 0 && b.b < nb) { sum += b.n; sq += b.n * b.n; }
        });
        const mean = sum / nb, std = Math.sqrt(Math.max(0, sq / nb - mean * mean)), thr = mean + cfg.anomalySigma * Math.max(std, 1);
        if (r.n > thr) { kind = 'spike'; detail = JSON.stringify({ views: r.n, mean: Math.round(mean * 100) / 100, std: Math.round(std * 100) / 100, threshold: Math.round(thr * 100) / 100 }); }
      }
      if (kind) {
        db.exec('BEGIN');
        try { q.insertAlert.run(r.ad_id, kind, detail, now); q.holdRecent.run(r.ad_id, start); db.exec('COMMIT'); flagged++; }
        catch (e) { db.exec('ROLLBACK'); throw e; }
      }
    });
    return flagged;
  }
  const detector = setInterval(function () { try { detect(); } catch (e) { console.error('detect error:', e.message); } }, cfg.anomalyIntervalMs);
  detector.unref();

  /* ---------- اربح مع m1li ---------- */
  const EARN_HOSTS = {
    tiktok: ['tiktok.com', 'vm.tiktok.com', 'vt.tiktok.com'],
    instagram: ['instagram.com', 'instagr.am'],
    facebook: ['facebook.com', 'fb.watch', 'fb.com']
  };
  const PAYOUT_METHODS = ['bank', 'wallet'];
  const submitTimes = new Map();   // user_id -> [timestamps]  (لا يُصفَّر بالحذف)
  function refCode(userId) { return 'M1-' + (userId * 7919 + 10007).toString(36).toUpperCase(); }
  /* يوحّد الرابط (بدون ?utm، بدون #، بدون / أخيرة) باش ما يتعاودش نفس الفيديو بصيغ مختلفة */
  function canonVideoUrl(platform, raw) {
    let u;
    try { u = new URL(String(raw || '').trim()); } catch (e) { return null; }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    if (u.username || u.password) return null;
    const host = u.hostname.toLowerCase().replace(/^(www|m|web|mobile|l)\./, '');
    const hosts = EARN_HOSTS[platform];
    if (!hosts || hosts.indexOf(host) === -1) return null;
    let path = u.pathname.replace(/\/+$/, '');
    if (path.length < 4) return null;   // الصفحة الرئيسية أو بروفايل بلا فيديو
    let keep = '';
    if (host === 'facebook.com' || host === 'fb.com') {   // روابط الفيديو القديمة كتخدم بـ ?v=ID
      const v = u.searchParams.get('v'); if (v && /^\d{5,25}$/.test(v)) keep = '?v=' + v;
      else if (!/\/(videos|reel|reels|watch|share)\b/i.test(path) && !/\/posts\//i.test(path)) return null;
    }
    if (host === 'tiktok.com' && !/\/(video|photo)\/\d+/.test(path) && !/^\/t\//.test(path) && !/^\/@[^/]+\/video/.test(path)) return null;
    if (host === 'instagram.com' && !/^\/(reel|reels|p|tv)\//.test(path) && !/^\/[^/]+\/(reel|p)\//.test(path)) return null;
    return 'https://' + host + path + keep;
  }
  function madOf(points) { return Math.round(points / cfg.earnPointsPerMad * 100) / 100; }
  function earnConfigPublic() {
    return { ok: true, pointsPerVideo: cfg.earnPointsPerVideo, pointsPerMad: cfg.earnPointsPerMad, minPayoutPoints: cfg.earnMinPayoutPoints,
      minPayoutMad: madOf(cfg.earnMinPayoutPoints), holdDays: cfg.earnHoldDays, submitPerDay: cfg.earnSubmitPerDay,
      platforms: Object.keys(EARN_HOSTS), methods: PAYOUT_METHODS };
  }
  function earnMe(user) {
    const now = Date.now();
    const available = Math.max(0, eq.plAvail.get(user.id, now).n), total = eq.plTotal.get(user.id).n;
    return { ok: true, refCode: refCode(user.id), available: available, availableMad: madOf(available),
      pending: Math.max(0, total - available), total: total,
      submissions: eq.vsMine.all(user.id), payouts: eq.poMine.all(user.id).map(function (r) { return Object.assign({}, r); }) };
  }
  function earnGuard(user) {
    if (otpEnabled && !user.verified) throw httpErr(403, 'phone_unverified');
  }
  function earnSubmit(user, body) {
    earnGuard(user);
    const platform = String(body.platform || '').toLowerCase();
    if (!EARN_HOSTS[platform]) throw httpErr(400, 'bad_platform');
    const raw = String(body.url || '').trim();
    if (!raw || raw.length > 500) throw httpErr(400, 'bad_url');
    const canon = canonVideoUrl(platform, raw);
    if (!canon) throw httpErr(400, 'bad_url');
    const row = eq.userById.get(user.id);
    if (cfg.earnMinAccountHours > 0 && Date.now() - row.created_at < cfg.earnMinAccountHours * 3600000) throw httpErr(403, 'account_too_new');
    if (eq.vsPendingCount.get(user.id).n >= cfg.earnMaxPending) throw httpErr(429, 'too_many_pending');
    if (eq.vsSince.get(user.id, Date.now() - 86400000).n >= cfg.earnSubmitPerDay) throw httpErr(429, 'daily_limit');
    if (recent(submitTimes, String(user.id), 86400000).length >= cfg.earnSubmitPerDay) throw httpErr(429, 'daily_limit');
    if (eq.vsByCanon.get(canon)) throw httpErr(409, 'duplicate_url');
    let id;
    try { id = Number(eq.vsInsert.run(user.id, platform, raw, canon, Date.now()).lastInsertRowid); }
    catch (e) { if (/UNIQUE/i.test(String(e && e.message))) throw httpErr(409, 'duplicate_url'); throw e; }
    recent(submitTimes, String(user.id), 86400000).push(Date.now());
    return { ok: true, id: id, status: 'pending' };
  }
  function earnPayout(user, body) {
    earnGuard(user);
    const method = String(body.method || '');
    if (PAYOUT_METHODS.indexOf(method) === -1) throw httpErr(400, 'bad_method');
    const holder = String(body.holder || '').trim().replace(/\s+/g, ' ');
    if (holder.length < 3 || holder.length > 60) throw httpErr(400, 'bad_holder');
    let account = String(body.account || '').replace(/[\s.\-]/g, '');
    if (method === 'bank') { if (!/^\d{24}$/.test(account)) throw httpErr(400, 'bad_rib'); }       // RIB مغربي: 24 رقم
    else { account = normPhone(account); if (!account || account.indexOf('212') !== 0) throw httpErr(400, 'bad_wallet'); }
    if (eq.poOpen.get(user.id).n > 0) throw httpErr(409, 'payout_open');
    const points = Math.floor(Number(body.points));
    if (!(points >= cfg.earnMinPayoutPoints)) throw httpErr(400, 'below_min');
    db.exec('BEGIN IMMEDIATE');
    try {
      const now = Date.now();
      if (eq.plAvail.get(user.id, now).n < points) throw httpErr(400, 'insufficient');
      const id = Number(eq.poInsert.run(user.id, points, madOf(points), method, holder, account, now).lastInsertRowid);
      eq.plAdd.run(user.id, -points, 'payout', id, now, now);
      db.exec('COMMIT');
      return { ok: true, id: id, points: points, amount_mad: madOf(points), status: 'pending' };
    } catch (e) { try { db.exec('ROLLBACK'); } catch (x) {} throw e; }
  }
  function earnReview(id, action, body) {
    const v = eq.vsGet.get(id);
    if (!v) throw httpErr(404, 'not_found');
    const now = Date.now(), note = String(body.note || '').slice(0, 200);
    db.exec('BEGIN IMMEDIATE');
    try {
      if (action === 'approve') {
        const pts = body.points === undefined ? cfg.earnPointsPerVideo : Math.floor(Number(body.points));
        if (!(pts >= 1 && pts <= cfg.earnMaxPointsPerVideo)) throw httpErr(400, 'bad_points');
        if (!eq.vsReview.run('approved', pts, note, now, id, 'pending').changes) throw httpErr(409, 'not_pending');
        eq.plAdd.run(v.user_id, pts, 'award', id, now + cfg.earnHoldDays * 86400000, now);
      } else if (action === 'reject') {
        if (!eq.vsReview.run('rejected', 0, note || 'مرفوض', now, id, 'pending').changes) throw httpErr(409, 'not_pending');
      } else if (action === 'revoke') {   // فيديو اتقبل ثم تمسح/تبيّن غش: كنسحبو النقاط
        if (!eq.vsReview.run('revoked', v.points_awarded, note || 'سُحبت النقاط', now, id, 'approved').changes) throw httpErr(409, 'not_approved');
        eq.plAdd.run(v.user_id, -v.points_awarded, 'revoke', id, now, now);
      } else throw httpErr(404, 'not_found');
      db.exec('COMMIT');
    } catch (e) { try { db.exec('ROLLBACK'); } catch (x) {} throw e; }
    return { ok: true };
  }
  function earnPayoutReview(id, action, body) {
    const r = eq.poGet.get(id);
    if (!r) throw httpErr(404, 'not_found');
    const now = Date.now(), note = String(body.note || '').slice(0, 200);
    db.exec('BEGIN IMMEDIATE');
    try {
      if (action === 'paid') {
        if (!eq.poSet.run('paid', note, now, id, 'pending').changes) throw httpErr(409, 'not_pending');
      } else if (action === 'reject') {   // كنرجّعو النقاط للمستخدم
        if (!eq.poSet.run('rejected', note || 'مرفوض', now, id, 'pending').changes) throw httpErr(409, 'not_pending');
        eq.plAdd.run(r.user_id, r.points, 'refund', id, now, now);
      } else throw httpErr(404, 'not_found');
      db.exec('COMMIT');
    } catch (e) { try { db.exec('ROLLBACK'); } catch (x) {} throw e; }
    return { ok: true };
  }

  function handleErr(res, e) {
    if (e && e.status) return send(res, e.status, { ok: false, error: e.code });
    console.error('error:', e); return send(res, 500, { ok: false, error: 'server_error' });
  }
  /* ---------- الإدارة ---------- */
  function admin(req, res, p, url) {
    if (req.method === 'GET' && p === '/api/admin/summary') {
      const by = {}; let counted = 0, rejected = 0;
      q.sumViews.all().forEach(function (r) { if (r.valid) counted += r.n; else { rejected += r.n; by[r.r] = (by[r.r] || 0) + r.n; } });
      return send(res, 200, { ok: true, views: { counted: counted, rejected: rejected, rejectedByReason: by }, likes: q.sumLikes.get().n, follows: q.sumFollows.get().n, openAlerts: q.sumOpen.get().n });
    }
    if (req.method === 'GET' && p === '/api/admin/alerts') {
      const st = url.searchParams.get('status');
      return send(res, 200, { ok: true, alerts: st ? q.alertListByStatus.all(st) : q.alertList.all() });
    }
    const m = /^\/api\/admin\/alerts\/(\d{1,12})\/(release|reject)$/.exec(p);
    if (req.method === 'POST' && m) {
      const a = q.alertGet.get(Number(m[1]));
      if (!a) throw httpErr(404, 'not_found');
      if (a.status !== 'open') throw httpErr(409, 'not_open');
      db.exec('BEGIN');
      try {
        if (m[2] === 'release') q.releaseHeld.run(a.ad_id);
        q.alertSet.run(m[2] === 'release' ? 'released' : 'rejected', a.id);
        db.exec('COMMIT');
      } catch (e) { db.exec('ROLLBACK'); throw e; }
      return send(res, 200, { ok: true, status: m[2] === 'release' ? 'released' : 'rejected' });
    }
    if (req.method === 'GET' && p === '/api/admin/orders') {
      const st = url.searchParams.get('status');
      const rows = ORDER_STATUSES.indexOf(st) !== -1 ? orderQ.listBy.all(st) : orderQ.list.all();
      return send(res, 200, { ok: true, orders: rows.map(shopOrderOut) });
    }
    const so = /^\/api\/admin\/orders\/(M1-[A-Z0-9]{3,12})\/status$/.exec(p);
    if (req.method === 'POST' && so) {
      return readJson(req).then(function (b) {
        const st = b && b.status;
        if (ORDER_STATUSES.indexOf(st) === -1) throw httpErr(400, 'bad_input');
        if (!orderQ.setStatus.run(st, Date.now(), so[1]).changes) throw httpErr(404, 'not_found');
        return send(res, 200, { ok: true, status: st });
      }).catch(function (e) { return handleErr(res, e); });
    }
    if (req.method === 'GET' && p === '/api/admin/apps') {
      return send(res, 200, { ok: true, apps: q.appAdminList.all() });
    }
    const ap = /^\/api\/admin\/apps\/([A-Za-z0-9_\-]{1,64})\/approve$/.exec(p);
    if (req.method === 'POST' && ap) {
      const r = q.appApprove.run(ap[1]);
      if (!r.changes) throw httpErr(404, 'not_found');
      return send(res, 200, { ok: true });
    }
    const rm = /^\/api\/admin\/apps\/([A-Za-z0-9_\-]{1,64})\/remove$/.exec(p);
    if (req.method === 'POST' && rm) {
      const r = q.appRemove.run(rm[1]);
      if (!r.changes) throw httpErr(404, 'not_found');
      dropPlayDir(rm[1]);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'GET' && p === '/api/admin/listings') return send(res, 200, { ok: true, items: listQ.adminList.all() });
    const lr = /^\/api\/admin\/listings\/([A-Za-z0-9_\-]{1,64})\/remove$/.exec(p);
    if (req.method === 'POST' && lr) {
      if (!listQ.remove.run(lr[1]).changes) throw httpErr(404, 'not_found');
      return send(res, 200, { ok: true });
    }
    if (req.method === 'GET' && p === '/api/admin/users') {
      return send(res, 200, { ok: true, total: q.userCount.get().n, users: q.userList.all().map(function (u) { return { id: u.id, phone: isGooglePhone(u.phone) ? '' : u.phone, email: u.email, name: u.name, verified: !!u.verified, created_at: u.created_at, last_seen: u.last_seen || 0 }; }) });
    }
    if (req.method === 'GET' && p === '/api/admin/metrics') {
      const n = Date.now(), d7 = n - 7 * 86400000, d30 = n - 30 * 86400000;
      const m = q.userMetrics.get(d7, d30, d7, d30, d7, d7, d7);
      return send(res, 200, { ok: true, total: m.total, new7: m.new7, new30: m.new30, active7: m.active7, active30: m.active30, returning7: m.returning7, older7: m.older7 });
    }
    if (req.method === 'GET' && p === '/api/admin/earn/summary') return send(res, 200, Object.assign({ ok: true }, eq.earnStats.get()));
    if (req.method === 'GET' && p === '/api/admin/earn/videos') {
      const st = url.searchParams.get('status') || 'pending';
      return send(res, 200, { ok: true, items: eq.vsAdminList.all(st).map(function (r) { r.ref = refCode(r.user_id); return r; }) });
    }
    if (req.method === 'GET' && p === '/api/admin/earn/payouts') return send(res, 200, { ok: true, items: eq.poAdminList.all(url.searchParams.get('status') || 'pending') });
    const ev = /^\/api\/admin\/earn\/videos\/(\d{1,12})\/(approve|reject|revoke)$/.exec(p);
    if (req.method === 'POST' && ev) return readJson(req).then(function (b) { return send(res, 200, earnReview(Number(ev[1]), ev[2], b || {})); }).catch(function (e) { return handleErr(res, e); });
    const ep = /^\/api\/admin\/earn\/payouts\/(\d{1,12})\/(paid|reject)$/.exec(p);
    if (req.method === 'POST' && ep) return readJson(req).then(function (b) { return send(res, 200, earnPayoutReview(Number(ep[1]), ep[2], b || {})); }).catch(function (e) { return handleErr(res, e); });
    throw httpErr(404, 'not_found');
  }

  /* ---------- طلبات المتجر (نسخة احتياطية من الطلبات + لوحة الإدارة) ---------- */
  const ORDER_STATUSES = ['new', 'confirmed', 'shipped', 'delivered', 'cancelled', 'returned'];
  const ORDER_ID_RE = /^M1-[A-Z0-9]{3,12}$/;
  const orderQ = {
    insert: db.prepare('INSERT OR IGNORE INTO shop_orders (id,status,name,phone,city,addr,note,items,sub,fee,disc,total,coupon,ip_hash,client_ts,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'),
    ipCount: db.prepare('SELECT COUNT(*) AS n FROM shop_orders WHERE ip_hash=? AND created_at>?'),
    list: db.prepare('SELECT * FROM shop_orders ORDER BY created_at DESC LIMIT 500'),
    listBy: db.prepare('SELECT * FROM shop_orders WHERE status=? ORDER BY created_at DESC LIMIT 500'),
    setStatus: db.prepare('UPDATE shop_orders SET status=?, updated_at=? WHERE id=?')
  };
  function str(v, max) { return String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, max); }
  function num(v) { const n = Number(v); if (!Number.isFinite(n) || n < 0 || n > 1e7) throw httpErr(400, 'bad_input'); return Math.round(n * 100) / 100; }
  function saveShopOrder(b, ipHash) {
    b = b || {};
    const id = str(b.id, 20); if (!ORDER_ID_RE.test(id)) throw httpErr(400, 'bad_input');
    const c = b.cust || {};
    const name = str(c.name, 80), phone = str(c.phone, 20), city = str(c.city, 60), addr = str(c.addr, 300), note = str(c.note, 300);
    if (!name || !/^\+?[0-9]{8,15}$/.test(phone) || !city || !addr) throw httpErr(400, 'bad_input');
    if (!Array.isArray(b.items) || !b.items.length || b.items.length > 50) throw httpErr(400, 'bad_input');
    const items = b.items.map(function (i) {
      const qty = Math.floor(Number(i && i.qty));
      if (!(qty >= 1 && qty <= 99)) throw httpErr(400, 'bad_input');
      return { id: str(i.id, 40), title: str(i.title, 120), price: num(i.price), qty: qty };
    });
    // حد: 10 طلبات/ساعة لكل IP حتى ما يتملأش الجدول بالسبام
    if (orderQ.ipCount.get(ipHash, Date.now() - 3600000).n >= 10) throw httpErr(429, 'too_many_orders');
    const r = orderQ.insert.run(id, 'new', name, phone, city, addr, note, JSON.stringify(items),
      num(b.sub), num(b.fee), num(b.disc), num(b.total), str(b.coupon, 40), ipHash, Math.floor(Number(b.ts)) || 0, Date.now());
    return { ok: true, duplicate: !r.changes };   // نفس الـ id مرتين = نجاح (idempotent)
  }
  function shopOrderOut(r) {
    let items = []; try { items = JSON.parse(r.items); } catch (e) {}
    return { id: r.id, status: r.status, ts: r.created_at, updatedAt: r.updated_at, cust: { name: r.name, phone: r.phone, city: r.city, addr: r.addr, note: r.note },
      items: items, sub: r.sub, fee: r.fee, disc: r.disc, total: r.total, coupon: r.coupon };
  }

  /* ---------- الراوتر ---------- */
  async function api(req, res, url, p) {
    const origin = cfg.allowedOrigin;
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Key, X-Admin-Token, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    const ipHash = hashIp(clientIp(req));
    if (rateLimited(ipHash)) return send(res, 429, { ok: false, error: 'rate_limited' }, { 'Retry-After': '60' });
    try {
      if (req.method === 'GET' && p === '/api/health') return send(res, 200, { ok: true });
      if (req.method === 'GET' && p === '/api/token') {
        const ad = String(url.searchParams.get('ad') || ''), dev = String(url.searchParams.get('d') || '');
        if (!AD_RE.test(ad) || !DEV_RE.test(dev)) throw httpErr(400, 'bad_input');
        return send(res, 200, { ok: true, token: makeToken(ad, dev) });
      }
      if (req.method === 'GET' && p === '/api/stats') return send(res, 200, stats(url));
      if (req.method === 'GET' && p === '/api/followers') {
        const dk = devKey(url.searchParams.get('dev')), d = String(url.searchParams.get('d') || '');
        return send(res, 200, { ok: true, followers: q.followCount.get(dk).n, following: DEV_RE.test(d) ? !!q.followGet.get(dk, d) : false });
      }
      if (req.method === 'POST' && p === '/api/orders') return send(res, 200, saveShopOrder(await readJson(req, 16384), ipHash));
      if (req.method === 'POST' && p === '/api/view') return send(res, 200, recordView(req, await readJson(req), ipHash));
      if (req.method === 'POST' && p === '/api/like') return send(res, 200, toggle(req, await readJson(req), 'like'));
      if (req.method === 'GET' && p === '/api/config') return send(res, 200, { ok: true, otp: otpEnabled, channel: cfg.otpChannel, nameAuth: !!cfg.nameAuth, googleClientId: cfg.nameAuth ? '' : cfg.googleClientId });
      if (req.method === 'POST' && p === '/api/auth/google' && cfg.nameAuth) throw httpErr(404, 'not_found');
      if (req.method === 'POST' && p === '/api/auth/google') return send(res, 200, await googleLogin(await readJson(req), ipHash));
      if (req.method === 'POST' && p === '/api/otp/send') return send(res, 200, await otpSend(req, await readJson(req), ipHash));
      if (req.method === 'POST' && p === '/api/otp/verify') {
        const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized');
        if (!otpEnabled) throw httpErr(404, 'otp_disabled');
        const b = await readJson(req);
        otpCheck(u.phone, b.code);
        q.userVerify.run(u.id); q.otpDel.run(u.phone);
        return send(res, 200, { ok: true, verified: true });
      }
      if (req.method === 'POST' && p === '/api/register') return send(res, 200, await register(await readJson(req), ipHash));
      if (req.method === 'POST' && p === '/api/login') return send(res, 200, await login(await readJson(req), ipHash));
      if (req.method === 'GET' && p === '/api/apps') {
        const me = authUser(req);
        return send(res, 200, { ok: true, apps: q.appList.all(Date.now(), me ? me.id : 0).map(function (r) { return appPublic(r, me); }) });
      }
      let am = /^\/api\/apps\/([A-Za-z0-9_\-]{1,64})$/.exec(p);
      if (req.method === 'GET' && am) {
        const r = q.appGet.get(am[1]);
        if (!r) throw httpErr(404, 'not_found');
        if (r.publish_at && r.publish_at > Date.now()) { const me0 = authUser(req); if (!me0 || me0.id !== r.user_id) throw httpErr(404, 'not_found'); }   // قيد النشر: يراه صاحبه فقط
        r.has_code = r.code !== '';
        const out = appPublic(r, authUser(req)); out.code = r.code;
        return send(res, 200, { ok: true, app: out });
      }
      if (req.method === 'POST' && p === '/api/apps') {
        const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized');
        const pubBody = await readJson(req, 1200000), pubOut = publishApp(u, pubBody);
        notifyNewApp(u, pubBody, pubOut.id);
        return send(res, 200, pubOut);
      }
      am = /^\/api\/apps\/([A-Za-z0-9_\-]{1,64})\/update$/.exec(p);
      if (req.method === 'POST' && am) {
        const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized');
        return send(res, 200, updateApp(u, am[1], await readJson(req, 1200000)));
      }
      if (req.method === 'POST' && p === '/api/apps/auto') {
        const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized');
        return send(res, 200, publishAppAuto(req, u, await readJson(req, 20000)));
      }
      if (req.method === 'GET' && p === '/api/listings') {
        const kind = url.searchParams.get('kind') === 'book' ? 'book' : 'product', me = authUser(req);
        return send(res, 200, { ok: true, items: listQ.byKind.all(kind).map(function (r) { return listingPublic(r, me); }) });
      }
      if (req.method === 'POST' && p === '/api/listings') {
        const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized');
        return send(res, 200, publishListing(u, await readJson(req, 20000)));
      }
      am = /^\/api\/listings\/([A-Za-z0-9_\-]{1,64})\/delete$/.exec(p);
      if (req.method === 'POST' && am) {
        const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized');
        return send(res, 200, deleteListing(u, am[1]));
      }
      if (req.method === 'POST' && p === '/api/upload') {
        const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized');
        return send(res, 200, await receiveUpload(req, res, u, url.searchParams.get('name')));
      }
      am = /^\/api\/apps\/([A-Za-z0-9_\-]{1,64})\/delete$/.exec(p);
      if (req.method === 'POST' && am) {
        const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized');
        const r = q.appGet.get(am[1]);
        if (!r) throw httpErr(404, 'not_found');
        if (r.user_id !== u.id) throw httpErr(403, 'forbidden');
        dropFile(u.id, r.apk_url); parseImgs(r.images).forEach(function (x) { dropFile(u.id, x); }); dropPlayDir(r.id);
        q.appDel.run(r.id);
        return send(res, 200, { ok: true });
      }
      if (req.method === 'GET' && p === '/api/me') { const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized'); return send(res, 200, { ok: true, user: publicUser(u) }); }
      if (req.method === 'POST' && p === '/api/logout') {
        const m = /^Bearer ([A-Za-z0-9_\-]{20,80})$/.exec(String(req.headers.authorization || ''));
        if (m) q.sessDel.run(crypto.createHash('sha256').update(m[1]).digest('hex'));
        return send(res, 200, { ok: true });
      }
      if (req.method === 'GET' && p === '/api/earn/config') return send(res, 200, earnConfigPublic());
      if (req.method === 'GET' && p === '/api/earn/me') { const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized'); return send(res, 200, earnMe(u)); }
      if (req.method === 'POST' && p === '/api/earn/submit') { const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized'); return send(res, 200, earnSubmit(u, await readJson(req))); }
      if (req.method === 'POST' && p === '/api/earn/payout') { const u = authUser(req); if (!u) throw httpErr(401, 'unauthorized'); return send(res, 200, earnPayout(u, await readJson(req))); }
      if (req.method === 'POST' && p === '/api/follow') return send(res, 200, toggle(req, await readJson(req), 'follow'));
      if (req.method === 'POST' && p === '/api/admin-login/code') return send(res, 200, await adminCodeSend(await readJson(req), ipHash));
      if (req.method === 'POST' && p === '/api/admin-login/verify') {
        if (adminBlocked(ipHash)) throw httpErr(429, 'too_many_attempts');
        try { return send(res, 200, adminCodeVerify(await readJson(req))); }
        catch (e) { if (e && e.status === 401) { const arr = adminFails.get(ipHash) || []; arr.push(Date.now()); adminFails.set(ipHash, arr); } throw e; }
      }
      if (req.method === 'POST' && p === '/api/admin-login') {
        if (adminBlocked(ipHash)) throw httpErr(429, 'too_many_attempts');
        try { return send(res, 200, adminLogin(await readJson(req))); }
        catch (e) { if (e && e.status === 401) { const arr = adminFails.get(ipHash) || []; arr.push(Date.now()); adminFails.set(ipHash, arr); } throw e; }
      }
      if (p.indexOf('/api/admin/') === 0) {
        if (adminBlocked(ipHash)) throw httpErr(429, 'too_many_attempts');
        if (!isAdmin(req)) { const arr = adminFails.get(ipHash) || []; arr.push(Date.now()); adminFails.set(ipHash, arr); throw httpErr(403, 'forbidden'); }
        return admin(req, res, p, url);
      }
      throw httpErr(404, 'not_found');
    } catch (e) {
      if (e && e.status) return send(res, e.status, e.report ? { ok: false, error: e.code, report: e.report } : { ok: false, error: e.code });
      console.error('error:', e);
      return send(res, 500, { ok: false, error: 'server_error' });
    }
  }

  /* ---------- الملفات الثابتة (مجلد dist) ---------- */
  function serveStatic(req, res, p) {
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    const root = path.resolve(cfg.staticDir);
    let rel;
    try { rel = decodeURIComponent(p); } catch (e) { res.writeHead(400); return res.end(); }
    if (rel.indexOf('\0') !== -1) { res.writeHead(400); return res.end(); }
    if (rel.slice(-1) === '/') rel += 'index.html';
    const full = path.resolve(root, '.' + path.sep + rel.replace(/^\/+/, ''));
    const relFromRoot = path.relative(root, full);
    if (!relFromRoot || relFromRoot.indexOf('..') === 0 || path.isAbsolute(relFromRoot) || relFromRoot.split(path.sep).some(function (s) { return s.charAt(0) === '.'; })) {
      res.writeHead(404); return res.end('Not found');
    }
    fs.stat(full, function (err, st) {
      if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
      const type = MIME[path.extname(full).toLowerCase()] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': type, 'Content-Length': st.size, 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
      if (req.method === 'HEAD') return res.end();
      fs.createReadStream(full).pipe(res);
    });
  }

  const server = http.createServer(function (req, res) {
    let url;
    try { url = new URL(req.url, 'http://localhost'); } catch (e) { res.writeHead(400); return res.end(); }
    const p = url.pathname;
    if (p.indexOf('/api/') === 0) { api(req, res, url, p).catch(function (e) { console.error(e); try { send(res, 500, { ok: false, error: 'server_error' }); } catch (x) {} }); return; }
    if (p.indexOf('/files/') === 0) return serveFile(req, res, p);
    if (p.indexOf('/play/') === 0) return servePlay(req, res, p);
    serveStatic(req, res, p);
  });
  server.requestTimeout = 10 * 60 * 1000;   // رفع APK من الهاتف قد يطول؛ headersTimeout (10s) يحمي من الاتصالات البطيئة
  server.headersTimeout = 10000;

  function close() { clearInterval(detector); clearInterval(cleaner); server.close(); try { db.close(); } catch (e) {} }
  return { server: server, db: db, cfg: cfg, detect: detect, close: close };
}

module.exports = { createApp: createApp, loadConfig: loadConfig };

if (require.main === module) {
  const app = createApp();
  if (!app.cfg.secretFromEnv) console.warn('⚠️  SECRET غير مضبوط: سيُنشأ سر عشوائي، وستبطل التوكنات عند كل إعادة تشغيل. ضع SECRET ثابتاً.');
  if (!app.cfg.otpWebhookUrl && app.cfg.otpMode !== 'console') console.warn('⚠️  تأكيد الرقم برمز غير مفعّل: ضع OTP_WEBHOOK_URL (بوابة SMS/واتساب) وإلا يُقبل أي رقم بدون تأكيد.');
  if (app.cfg.otpMode === 'console' && !app.cfg.otpWebhookUrl) console.warn('⚠️  OTP_MODE=console: الرموز تُطبع في السجل فقط (للتجريب، ليس للإنتاج).');
  if (app.cfg.adminEmail && !(app.cfg.mailer || (app.cfg.smtpUser && app.cfg.smtpPass))) console.warn('ℹ️  SMTP_USER/SMTP_PASS غير مضبوطين: كود الدخول وإشعارات التطبيقات الجديدة بالإيميل معطّلة (تبقى فصفحة الإدارة).');
  if ((app.cfg.adminEmail || app.cfg.adminPhone) && !app.cfg.adminPasswordHash && app.cfg.adminPassword.length < 12) console.warn('⚠️  ADMIN_PASSWORD أقصر من 12 حرف: دخول الإدارة بالإيميل معطّل.');
  if (!app.cfg.adminKey) console.warn('ℹ️  ADMIN_KEY غير مضبوط: واجهة الإدارة /api/admin معطّلة.');
  if (app.cfg.allowedOrigin === '*') console.warn('ℹ️  ALLOWED_ORIGIN = * : ضع نطاق متجرك الحقيقي في الإنتاج.');
  app.server.listen(app.cfg.port, app.cfg.host, function () { console.log('M1li server: http://' + app.cfg.host + ':' + app.cfg.port); });
  const stop = function () { app.close(); process.exit(0); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}
