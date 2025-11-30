import express, { type RequestHandler } from "express";
import session from "express-session";
import connectPg from "connect-pg-simple";

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

export function getAdminSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1000; // 1 week
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: true, // يمكن تركه true لتوليد الجدول تلقائياً
    ttl: sessionTtl,
    tableName: "sessions",
  });

  return session({
    secret: process.env.SESSION_SECRET!,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // HTTPS فقط
      maxAge: sessionTtl,
      sameSite: process.env.NODE_ENV === "production" ? "lax" : "lax",
    },
  });
}


export const isAdminAuthenticated: RequestHandler = (req, res, next) => {
  const session = (req as any).session;
  if (session?.adminId) {
    return next();
  }
  res.status(401).json({ message: "Unauthorized" });
};

export function setupAdminAuth(app: express.Express) {
  app.use(getAdminSession());

  // Admin login
  app.post("/api/admin/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "اسم المستخدم وكلمة المرور مطلوبان" });
    }

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      (req as any).session.adminId = "admin";
      (req as any).session.save((err) => {
        if (err) {
          return res.status(500).json({ message: "فشل تسجيل الدخول" });
        }
        res.json({ success: true });
      });
    } else {
      res.status(401).json({ message: "اسم المستخدم أو كلمة المرور غير صحيحة" });
    }
  });

  // Admin logout
  app.post("/api/admin/logout", (req, res) => {
    (req as any).session.adminId = null;
    (req as any).session.save((err) => {
      if (err) {
        return res.status(500).json({ message: "فشل تسجيل الخروج" });
      }
      res.json({ success: true });
    });
  });

  // Check admin auth status
  app.get("/api/admin/auth-status", (req, res) => {
    const session = (req as any).session;
    res.json({ isAuthenticated: !!session?.adminId });
  });
}
