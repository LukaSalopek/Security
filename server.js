const express = require("express");
const cookieParser = require("cookie-parser");
const { randomBytes, scryptSync, timingSafeEqual, createCipheriv } = require("crypto");

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const baza = { poruke: [], korisnici: [], ukradeniKolacici: [] };
const postavke = { xssRanjivost: true, sdeRanjivost: true };

app.post("/xss/poruka", (req, res) => {
  if (req.body.poruka) baza.poruke.push(req.body.poruka);
  res.redirect("/");
});

app.post("/xss/obrisi", (req, res) => {
  baza.poruke = [];
  res.redirect("/");
});

function sekcijaXss() {
  const poruke = baza.poruke
    .map((p) => `<li>${p}</li>`)
    .join("");
  return `<section>
<h2>Cross-site scripting (XSS) – pohranjeni</h2>
<p class="upute"><b>Upute:</b> Upiši poruku koja se pohranjuje na poslužitelju i prikazuje svim posjetiteljima. Isprobaj:<br>
<code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code><br>
<code>&lt;img src=x onerror="alert(document.cookie)"&gt;</code></p>
<form method="post" action="/xss/poruka">
Poruka: <input name="poruka" size="60"> <button>Spremi poruku</button>
</form>
<form method="post" action="/xss/obrisi"><button>Obriši poruke</button></form>
<h3>Poruke</h3>
<ul>${poruke}</ul>
</section>`;
}

function sekcijaSde() {
  return `<section><h2>Nesigurna pohrana osjetljivih podataka (Sensitive Data Exposure)</h2><p>(uskoro)</p></section>`;
}

app.get("/", (req, res) => {
  const sid = req.cookies.sessionId || randomBytes(8).toString("hex");
  res.cookie("sessionId", sid);
  res.send(`<!DOCTYPE html>
<html lang="hr">
<head>
<meta charset="utf-8">
<title>Drugi projekt</title>
<style>
body { font-family: Arial; max-width: 900px; margin: auto; padding: 16px; }
section { border-top: 1px dashed #888; margin-top: 20px; }
.upute { font-style: italic; }
code { background: #ffff66; font-style: normal; }
table { border-collapse: collapse; }
td, th { border: 1px solid #999; padding: 4px; font-size: 13px; word-break: break-all; }
form { margin: 6px 0; }
</style>
</head>
<body>
<h1>Drugi projekt</h1>
${sekcijaXss()}
${sekcijaSde()}
</body>
</html>`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server radi: http://localhost:" + PORT));