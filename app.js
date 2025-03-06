const express = require("express"); // استيراد مكتبة Express لإنشاء الخادم

const jwt = require("jsonwebtoken"); // استيراد مكتبة JSON Web Token لإدارة التحقق من الهوية
const bcrypt = require("bcryptjs"); // استيراد مكتبة bcrypt لتشفير كلمات المرور
const bodyParser = require("body-parser"); // استيراد مكتبة body-parser لتحليل بيانات الطلب
const cookieParser = require("cookie-parser"); // استيراد مكتبة cookie-parser للتعامل مع الكوكيز
const { v4: uuidv4 } = require("uuid"); // استيراد مكتبة uuid لإنشاء معرّفات فريدة
require("dotenv").config(); // استيراد مكتبة dotenv لتحميل المتغيرات البيئية من ملف .env

const app = express(); // إنشاء تطبيق Express
app.use(bodyParser.json()); // استخدام body-parser لتحليل بيانات JSON في الطلبات
app.use(cookieParser()); // استخدام cookie-parser للتعامل مع الكوكيز

const PORT = process.env.PORT || 5000; // تحديد المنفذ الذي سيعمل عليه الخادم
const SECRET_KEY = process.env.SECRET_KEY || "supersecretkey"; // مفتاح سري لإنشاء التوكن
const REFRESH_SECRET = process.env.REFRESH_SECRET || "refreshsupersecret"; // مفتاح سري لإنشاء توكن التحديث
const TOKEN_EXPIRY = "1h"; // مدة صلاحية التوكن الرئيسي
const REFRESH_EXPIRY = "7d"; // مدة صلاحية توكن التحديث

// قاعدة بيانات وهمية (يجب استبدالها بقاعدة بيانات حقيقية)
const users = []; // مصفوفة لتخزين المستخدمين المسجلين
const refreshTokens = new Map(); // تخزين توكنات التحديث المرتبطة بالمستخدمين

// **تسجيل مستخدم جديد**
app.post("/register", async (req, res) => {
  const { username, password, role } = req.body; // استخراج البيانات من الطلب

  if (!username || !password || !role) { // التحقق من صحة البيانات المدخلة
    return res.status(400).json({ message: "جميع الحقول مطلوبة" });
  }

  // التحقق مما إذا كان المستخدم مسجل مسبقًا
  if (users.some((u) => u.username === username)) {
    return res.status(400).json({ message: "المستخدم موجود بالفعل" });
  }

  // تشفير كلمة المرور قبل تخزينها
  const hashedPassword = await bcrypt.hash(password, 10);

  // إضافة المستخدم الجديد إلى قاعدة البيانات الوهمية
  users.push({ id: uuidv4(), username, password: hashedPassword, role });

  res.status(201).json({ message: "تم تسجيل المستخدم بنجاح" });
});

// **تسجيل الدخول وإنشاء توكنات الوصول والتحديث**
app.post("/login", async (req, res) => {
  const { username, password } = req.body; // استخراج بيانات تسجيل الدخول
  const user = users.find((u) => u.username === username); // البحث عن المستخدم في قاعدة البيانات

  // التحقق من صحة بيانات تسجيل الدخول
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "بيانات الاعتماد غير صحيحة" });
  }

  // إنشاء توكن الوصول وتوكن التحديث
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  refreshTokens.set(refreshToken, user.username); // تخزين توكن التحديث في الخريطة

  res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: false }); // تخزين توكن التحديث في الكوكيز
  res.json({ accessToken }); // إرسال توكن الوصول إلى المستخدم
});

// **وظيفة للتحقق من التوكن**
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // استخراج التوكن من الطلب
  if (!token) return res.status(403).json({ message: "تم رفض الوصول" }); // في حال عدم وجود توكن

  // التحقق من صحة التوكن
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "التوكن غير صالح" });
    req.user = decoded; // تخزين بيانات المستخدم في الطلب
    next(); // المتابعة إلى الوظيفة التالية
  });
};

// **وظيفة للتحقق من صلاحيات المستخدم بناءً على الدور**
const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) { // التحقق من أن دور المستخدم مصرح له بالوصول
      return res.status(403).json({ message: "ممنوع: ليس لديك الصلاحيات الكافية" });
    }
    next();
  };
};

// **مسار محمي خاص بالمشرفين**
app.get("/admin", verifyToken, authorize(["admin"]), (req, res) => {
  res.json({ message: `مرحبًا أيها المشرف ${req.user.username}` });
});

// **تحديث توكن الوصول باستخدام توكن التحديث**
app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken; // استخراج توكن التحديث من الكوكيز

  // التحقق من صحة توكن التحديث
  if (!refreshToken || !refreshTokens.has(refreshToken)) {
    return res.status(403).json({ message: "توكن التحديث غير صالح" });
  }

  jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "توكن التحديث غير صالح" });

    // إنشاء توكن وصول جديد
    const newAccessToken = generateAccessToken({ id: decoded.id, username: decoded.username, role: decoded.role });
    res.json({ accessToken: newAccessToken });
  });
});

// **تسجيل الخروج (إلغاء صلاحية توكن التحديث)**
app.post("/logout", (req, res) => {
  const refreshToken = req.cookies.refreshToken; // استخراج توكن التحديث

  if (refreshToken) {
    refreshTokens.delete(refreshToken); // حذف توكن التحديث من القائمة
  }

  res.clearCookie("refreshToken"); // حذف الكوكيز من المتصفح
  res.json({ message: "تم تسجيل الخروج بنجاح" });
});

// **وظيفة لإنشاء توكن الوصول**
const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: TOKEN_EXPIRY });
};

// **وظيفة لإنشاء توكن التحديث**
const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
};

// **تشغيل الخادم**
app.listen(PORT, () => console.log(`الخادم يعمل على المنفذ ${PORT}`));
