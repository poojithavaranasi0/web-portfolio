
require("dotenv").config();
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const passport = require("./passport");
const app = express();
const PORT = 3000;

const portfolioDir = path.join(__dirname, "..", "portfolio-main");

// Check environment variables
if (
  !process.env.SESSION_SECRET ||
  !process.env.ADMIN_EMAIL ||
  !process.env.ADMIN_PASSWORD_HASH
) {
  throw new Error("Check SESSION_SECRET, ADMIN_EMAIL and ADMIN_PASSWORD_HASH in .env");
}

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Session configuration
app.use(session({
  name: "portfolio.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false, // Local development only
    maxAge: 30 * 60 * 1000
  }
}));
// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());
// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }

  return res.redirect("/login");
}

// Home route
app.get("/", (req, res) => {
  res.redirect("/login");
});

// Login page
app.get("/login", (req, res) => {
  res.sendFile(path.join(portfolioDir, "login.html"));
});

// Login verification
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    email.length > 254 ||
    password.length > 72 ||
    email.trim().toLowerCase() !==
      process.env.ADMIN_EMAIL.trim().toLowerCase()
  ) {
    return res.status(401).send("Invalid email or password.");
  }

  try {
    const validPassword = await bcrypt.compare(
      password,
      process.env.ADMIN_PASSWORD_HASH
    );

    if (!validPassword) {
      return res.status(401).send("Invalid email or password.");
    }

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).send("Could not create login session.");
      }

      req.session.authenticated = false;
      req.session.pendingMfa = true;

      req.session.save((saveErr) => {
        if (saveErr) {
          return res.status(500).send("Could not save login session.");
        }

        res.redirect("/mfa");
      });
    });
  } catch (error) {
    console.error("Login verification failed.");
    return res.status(500).send("Login could not be completed.");
  }
});

// Public CSS - required for login page styling
app.get("/style.css", (req, res) => {
  res.sendFile(path.join(portfolioDir, "style.css"));
});
// Start Google login
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  })
);

// Google OAuth callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  (req, res) => {
    req.session.authenticated = false;
    req.session.pendingMfa = true;

    req.session.save((err) => {
      if (err) {
        return res.status(500).send("Could not save login session.");
      }

      res.redirect("/mfa");
    });
  }
);
// MFA verification page
app.get("/mfa", (req, res) => {
  if (!req.session.pendingMfa) {
    return res.redirect("/login");
  }

  const secret = process.env.MFA_SECRET;

  if (!secret) {
    return res.status(500).send("MFA secret is missing.");
  }

  const otpUrl = speakeasy.otpauthURL({
    secret: secret,
    encoding: "base32",
    label: "Portfolio Login",
    issuer: "Portfolio Authentication"
  });

  QRCode.toDataURL(otpUrl, (err, qrCode) => {
    if (err) {
      return res.status(500).send("Could not generate MFA QR code.");
    }

    
res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Your Account | Portfolio</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: Arial, sans-serif;
      background: #f1f4f9;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      color: #202124;
    }

    .card {
      background: white;
      width: 100%;
      max-width: 460px;
      padding: 35px;
      border-radius: 18px;
      text-align: center;
      box-shadow: 0 8px 30px rgba(0,0,0,0.08);
    }

    .logo {
      color: #4285f4;
      font-size: 28px;
      font-weight: bold;
      margin-bottom: 15px;
    }

    h2 {
      font-size: 24px;
      margin-bottom: 10px;
    }

    .description {
      color: #666;
      line-height: 1.6;
      font-size: 14px;
    }

    .qr-box {
      margin: 25px auto;
      padding: 15px;
      width: fit-content;
      border: 1px solid #e0e0e0;
      border-radius: 12px;
      background: white;
    }

    .qr-box img {
      width: 190px;
      height: 190px;
      display: block;
    }

    .steps {
      text-align: left;
      background: #f7f9fc;
      padding: 15px 20px;
      border-radius: 10px;
      font-size: 14px;
      line-height: 1.8;
      color: #555;
    }

    input {
      width: 100%;
      padding: 14px;
      margin: 20px 0 15px;
      border: 1px solid #ccc;
      border-radius: 8px;
      font-size: 22px;
      text-align: center;
      letter-spacing: 8px;
      outline: none;
    }

    input:focus {
      border-color: #4285f4;
      box-shadow: 0 0 0 3px rgba(66,133,244,0.12);
    }

    button {
      width: 100%;
      padding: 14px;
      background: #4285f4;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: bold;
      cursor: pointer;
      transition: 0.3s;
    }

    button:hover {
      background: #286bd1;
    }

    .footer {
      color: #888;
      font-size: 12px;
      margin-top: 22px;
    }
  </style>
</head>

<body>
  <div class="card">

    <div class="logo">Portfolio Security</div>

    <h2>Two-Step Verification</h2>

    <p class="description">
      Protect your account with an additional layer of security.
      Scan the QR code using Microsoft Authenticator.
    </p>

    <div class="qr-box">
      <img src="${qrCode}" alt="MFA QR Code">
    </div>
    <form action="/mfa/verify" method="POST">
      <input
        type="text"
        name="token"
        placeholder="000000"
        inputmode="numeric"
        pattern="[0-9]{6}"
        maxlength="6"
        autocomplete="one-time-code"
        required
      >

      <button type="submit">Verify & Continue</button>
    </form>

    <div class="footer">
      Your account is protected with two-factor authentication.
    </div>

  </div>
</body>
</html>
`);
  });
});

// Verify MFA code
app.post("/mfa/verify", (req, res) => {
  if (!req.session.pendingMfa) {
    return res.redirect("/login");
  }

  const verified = speakeasy.totp.verify({
    secret: process.env.MFA_SECRET,
    encoding: "base32",
    token: req.body.token,
    window: 1
  });

  if (!verified) {
    return res.status(401).send("Invalid code. Please try again.");
  }

  req.session.authenticated = true;
  req.session.pendingMfa = false;

  req.session.save((err) => {
    if (err) {
      return res.status(500).send("Could not save MFA session.");
    }

    res.redirect("/portfolio");
  });
});
// Protected portfolio page
app.get("/portfolio", isAuthenticated, (req, res) => {
  res.sendFile(path.join(portfolioDir, "index.html"));
});

// Protected JavaScript
app.get("/script.js", isAuthenticated, (req, res) => {
  res.sendFile(path.join(portfolioDir, "script.js"));
});

// Protected profile image
app.get("/profile.jpg", isAuthenticated, (req, res) => {
  res.sendFile(path.join(portfolioDir, "profile.jpg"));
});

// Protected resume
app.get("/Resume.pdf", isAuthenticated, (req, res) => {
  res.sendFile(path.join(portfolioDir, "Resume.pdf"));
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Could not log out.");
    }

    res.clearCookie("portfolio.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: false
    });

    res.redirect("/login");
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Authentication server running at http://localhost:${PORT}`);
});
