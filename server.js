const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const helmet = require("helmet");

const app = express();
const PORT = process.env.PORT || 3000;

const db = new Database("codementor.db");

db.prepare(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    xp INTEGER DEFAULT 0
)
`).run();

app.use(helmet());

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 24 * 60 * 60 * 1000
    }
}));

function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            error: "Avval tizimga kiring."
        });
    }
    next();
}


/* REGISTER */

app.post("/api/register", async (req, res) => {

    try {

        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                error: "Barcha maydonlarni to‘ldiring."
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                error: "Parol kamida 8 ta belgidan iborat bo‘lsin."
            });
        }

        const oldUser = db
            .prepare("SELECT id FROM users WHERE email = ?")
            .get(email);

        if (oldUser) {
            return res.status(400).json({
                error: "Bu email allaqachon mavjud."
            });
        }

        const hash = await bcrypt.hash(password, 12);

        const result = db.prepare(`
            INSERT INTO users
            (name, email, password)
            VALUES (?, ?, ?)
        `).run(name, email, hash);

        req.session.userId = result.lastInsertRowid;

        res.json({
            success: true
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Server xatosi."
        });

    }

});


/* LOGIN */

app.post("/api/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        const user = db
            .prepare("SELECT * FROM users WHERE email = ?")
            .get(email);

        if (!user) {
            return res.status(401).json({
                error: "Email yoki parol noto‘g‘ri."
            });
        }

        const correct =
            await bcrypt.compare(password, user.password);

        if (!correct) {
            return res.status(401).json({
                error: "Email yoki parol noto‘g‘ri."
            });
        }

        req.session.userId = user.id;

        res.json({
            success: true
        });

    } catch (error) {

        res.status(500).json({
            error: "Server xatosi."
        });

    }

});


/* USER */

app.get("/api/me", requireLogin, (req, res) => {

    const user = db
        .prepare(`
            SELECT id, name, email, xp
            FROM users
            WHERE id = ?
        `)
        .get(req.session.userId);

    if (!user) {
        return res.status(404).json({
            error: "Foydalanuvchi topilmadi."
        });
    }

    const level =
        Math.floor(user.xp / 50) + 1;

    res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        xp: user.xp,
        level
    });

});


/* XP */

app.post("/api/xp", requireLogin, (req, res) => {

    const amount = Number(req.body.amount);

    if (
        !Number.isInteger(amount) ||
        amount <= 0 ||
        amount > 10
    ) {
        return res.status(400).json({
            error: "Noto‘g‘ri XP."
        });
    }

    db.prepare(`
        UPDATE users
        SET xp = xp + ?
        WHERE id = ?
    `).run(
        amount,
        req.session.userId
    );

    const user = db
        .prepare("SELECT xp FROM users WHERE id = ?")
        .get(req.session.userId);

    res.json({
        xp: user.xp,
        level: Math.floor(user.xp / 50) + 1
    });

});


/* LOGOUT */

app.post("/api/logout", requireLogin, (req, res) => {

    req.session.destroy(() => {

        res.json({
            success: true
        });

    });

});


/* WEBSITE */

const HTML = `

<!DOCTYPE html>

<html lang="uz">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>CodeMentor AI</title>

<style>

*{
    box-sizing:border-box;
    margin:0;
    padding:0;
}

html{
    scroll-behavior:smooth;
}

body{
    font-family:Arial,sans-serif;
    background:#f5f7fb;
    color:#172033;
}

.hidden{
    display:none!important;
}


/* LOGIN */

#authPage{
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:20px;
    background:linear-gradient(
        135deg,
        #111827,
        #2563eb
    );
}

.auth-box{
    width:100%;
    max-width:420px;
    background:white;
    padding:40px 30px;
    border-radius:22px;
    text-align:center;
    box-shadow:0 20px 60px rgba(0,0,0,.25);
}

.logo{
    font-size:55px;
}

.auth-box h1{
    margin:10px 0;
}

.auth-box p{
    color:#667085;
    margin:15px 0;
}

.auth-box input{
    width:100%;
    padding:14px;
    margin:6px 0;
    border:1px solid #ddd;
    border-radius:10px;
}

.auth-box button{
    width:100%;
    padding:14px;
    margin-top:10px;
    border:0;
    border-radius:10px;
    background:#2563eb;
    color:white;
    font-weight:bold;
}

.auth-box span{
    color:#2563eb;
    font-weight:bold;
    cursor:pointer;
}

.error{
    color:#dc2626;
    margin-top:15px;
}


/* HEADER */

header{
    position:sticky;
    top:0;
    z-index:10;
    height:70px;
    padding:0 7%;
    display:flex;
    align-items:center;
    justify-content:space-between;
    background:#111827;
    color:white;
}

.logo-small{
    font-size:20px;
    font-weight:bold;
}

nav{
    display:flex;
    align-items:center;
    gap:18px;
}

nav a{
    color:white;
    text-decoration:none;
}

.logout{
    border:0;
    padding:9px 14px;
    border-radius:8px;
    background:#dc2626;
    color:white;
}


/* HERO */

.hero{
    min-height:520px;
    display:flex;
    align-items:center;
    padding:70px 8%;
    color:white;
    background:linear-gradient(
        135deg,
        #111827,
        #2563eb
    );
}

.hero h1{
    font-size:52px;
}

.hero h1 span{
    color:#60a5fa;
}

.hero p{
    max-width:650px;
    margin:25px 0;
    font-size:19px;
    line-height:1.6;
}

.hero button{
    padding:15px 25px;
    border:0;
    border-radius:10px;
    color:#2563eb;
    font-weight:bold;
}


/* SECTIONS */

section{
    padding:70px 8%;
}

section>h2{
    text-align:center;
    margin-bottom:35px;
    font-size:32px;
}


/* COURSES */

.course-grid{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:20px;
}

.course{
    padding:30px 20px;
    background:white;
    border-radius:18px;
    text-align:center;
    cursor:pointer;
    box-shadow:0 8px 30px rgba(0,0,0,.07);
    transition:.3s;
}

.course:hover{
    transform:translateY(-7px);
}

.course-icon{
    font-size:48px;
}

.course h3{
    margin:15px 0 8px;
}

.course p{
    color:#667085;
}


/* AI */

.ai-section{
    background:#111827;
    color:white;
}

.ai-box{
    max-width:850px;
    margin:auto;
    background:#1f2937;
    border-radius:18px;
    overflow:hidden;
}

.ai-header{
    padding:18px;
    background:#2563eb;
    font-weight:bold;
}

.chat{
    height:320px;
    padding:20px;
    overflow-y:auto;
}

.message{
    max-width:75%;
    padding:13px;
    margin-bottom:12px;
    border-radius:12px;
}

.ai{
    background:#374151;
}

.user{
    margin-left:auto;
    background:#2563eb;
}

.chat-input{
    display:flex;
    gap:10px;
    padding:15px;
}

.chat-input input{
    flex:1;
    padding:13px;
    border:0;
    border-radius:10px;
    background:#111827;
    color:white;
}

.chat-input button{
    padding:0 20px;
    border:0;
    border-radius:10px;
    background:#60a5fa;
}


/* PRACTICE */

.practice{
    max-width:900px;
    margin:auto;
    padding:25px;
    border-radius:18px;
    background:#111827;
    color:white;
}

.practice textarea{
    width:100%;
    height:220px;
    margin:20px 0;
    padding:15px;
    background:#020617;
    color:white;
    border:1px solid #374151;
    border-radius:10px;
    font-family:monospace;
}

.practice button{
    padding:13px 20px;
    border:0;
    border-radius:9px;
    background:#2563eb;
    color:white;
}

#result{
    margin-top:15px;
    padding:12px;
}


/* PROFILE */

#profile{
    background:#eef2ff;
}

.profile{
    max-width:700px;
    margin:auto;
    padding:30px;
    background:white;
    border-radius:18px;
    text-align:center;
}

.avatar{
    width:80px;
    height:80px;
    margin:auto;
    display:flex;
    align-items:center;
    justify-content:center;
    border-radius:50%;
    background:#2563eb;
    font-size:38px;
}

.stats{
    margin:25px 0;
    font-size:18px;
}

.progress{
    width:100%;
    height:12px;
    background:#ddd;
    border-radius:20px;
    overflow:hidden;
}

#progressBar{
    width:0%;
    height:100%;
    background:#2563eb;
}


/* FOOTER */

footer{
    padding:25px;
    text-align:center;
    background:#111827;
    color:white;
}


/* MOBILE */

@media(max-width:800px){

    nav a{
        display:none;
    }

    .course-grid{
        grid-template-columns:repeat(2,1fr);
    }

    .hero h1{
        font-size:40px;
    }

}

@media(max-width:500px){

    .course-grid{
        grid-template-columns:1fr;
    }

    section{
        padding:50px 5%;
    }

    .hero{
        padding:50px 6%;
    }

    .hero h1{
        font-size:34px;
    }

    .chat-input{
        flex-direction:column;
    }

    .chat-input button{
        padding:13px;
    }

}

</style>

</head>

<body>


<!-- LOGIN -->

<div id="authPage">

<div class="auth-box">

<div class="logo">💻</div>

<h1>CodeMentor AI</h1>

<p>Dasturlashni AI bilan o‘rganing 🚀</p>


<div id="loginForm">

<input
id="loginEmail"
type="email"
placeholder="Email">

<input
id="loginPassword"
type="password"
placeholder="Parol">

<button onclick="login()">
🔐 Kirish
</button>

<p>
Hisobingiz yo‘qmi?
<span onclick="showRegister()">
Ro‘yxatdan o‘tish
</span>
</p>

</div>


<div
id="registerForm"
class="hidden">

<input
id="registerName"
type="text"
placeholder="Ismingiz">

<input
id="registerEmail"
type="email"
placeholder="Email">

<input
id="registerPassword"
type="password"
placeholder="Parol — 8+ belgi">

<button onclick="register()">
🚀 Ro‘yxatdan o‘tish
</button>

<p>
Hisobingiz bormi?
<span onclick="showLogin()">
Kirish
</span>
</p>

</div>


<div
id="authMessage"
class="error">
</div>

</div>

</div>


<!-- MAIN -->

<div
id="mainPage"
class="hidden">


<header>

<div class="logo-small">
💻 CodeMentor AI
</div>

<nav>

<a href="#courses">Kurslar</a>

<a href="#ai">AI</a>

<a href="#practice">Amaliyot</a>

<a href="#profile">Profil</a>

<button
class="logout"
onclick="logout()">
Chiqish
</button>

</nav>

</header>


<section class="hero">

<div>

<h1>
Salom,
<span id="userName">Dasturchi</span>! 👋
</h1>

<p>
Dasturlashni kurslar,
amaliy topshiriqlar va
AI Mentor yordamida o‘rganing.
</p>

<button onclick="goCourses()">
🚀 Boshlash
</button>

</div>

</section>


<!-- COURSES -->

<section id="courses">

<h2>📚 Kurslar</h2>

<div class="course-grid">


<div
class="course"
onclick="selectCourse('HTML')">

<div class="course-icon">🌐</div>

<h3>HTML</h3>

<p>Web sahifa yaratish.</p>

</div>


<div
class="course"
onclick="selectCourse('CSS')">

<div class="course-icon">🎨</div>

<h3>CSS</h3>

<p>Sayt dizayni.</p>

</div>


<div
class="course"
onclick="selectCourse('JavaScript')">

<div class="course-icon">⚡</div>

<h3>JavaScript</h3>

<p>Interaktiv saytlar.</p>

</div>


<div
class="course"
onclick="selectCourse('Python')">

<div class="course-icon">🐍</div>

<h3>Python</h3>

<p>Dasturlash asoslari.</p>

</div>


</div>

</section>


<!-- AI -->

<section
id="ai"
class="ai-section">

<h2>🤖 AI Mentor</h2>

<div class="ai-box">

<div class="ai-header">
CodeMentor AI Mentor
</div>

<div
id="chat"
class="chat">

<div class="message ai">
Salom! 👋 HTML, CSS,
JavaScript yoki Python
haqida savol bering.
</div>

</div>

<div class="chat-input">

<input
id="aiInput"
placeholder="Savolingiz...">

<button onclick="sendAI()">
Yuborish
</button>

</div>

</div>

</section>


<!-- PRACTICE -->

<section id="practice">

<h2>💻 Amaliyot</h2>

<div class="practice">

<h3 id="taskTitle">
HTML topshirig‘i
</h3>

<p id="taskText">
&lt;h1&gt; tegidan foydalanib
sarlavha yarating.
</p>

<textarea
id="code"
placeholder="Kodingizni yozing..."></textarea>

<button onclick="checkCode()">
✅ Tekshirish
</button>

<div id="result">
Natija shu yerda chiqadi.
</div>

</div>

</section>


<!-- PROFILE -->

<section id="profile">

<h2>👤 Profil</h2>

<div class="profile">

<div class="avatar">
👨‍💻
</div>

<h3 id="profileName">-</h3>

<p id="profileEmail">-</p>

<div class="stats">

⭐ XP:
<b id="xp">0</b>

&nbsp;&nbsp;

🏆 Level:
<b id="level">1</b>

</div>

<div class="progress">

<div id="progressBar"></div>

</div>

</div>

</section>


<footer>
© 2026 CodeMentor AI
</footer>

</div>


<script>


/* REGISTER */

async function register(){

    const name =
        document
        .getElementById("registerName")
        .value.trim();

    const email =
        document
        .getElementById("registerEmail")
        .value.trim();

    const password =
        document
        .getElementById("registerPassword")
        .value;


    const response =
        await fetch(
            "/api/register",
            {
                method:"POST",

                headers:{
                    "Content-Type":
                    "application/json"
                },

                body:JSON.stringify({
                    name,
                    email,
                    password
                })
            }
        );


    const data =
        await response.json();


    if(!response.ok){

        showError(data.error);

        return;
    }


    await loadUser();

}


/* LOGIN */

async function login(){

    const email =
        document
        .getElementById("loginEmail")
        .value.trim();

    const password =
        document
        .getElementById("loginPassword")
        .value;


    const response =
        await fetch(
            "/api/login",
            {
                method:"POST",

                headers:{
                    "Content-Type":
                    "application/json"
                },

                body:JSON.stringify({
                    email,
                    password
                })
            }
        );


    const data =
        await response.json();


    if(!response.ok){

        showError(data.error);

        return;
    }


    await loadUser();

}


function showError(message){

    document
    .getElementById("authMessage")
    .innerText = message;

}


function showRegister(){

    document
    .getElementById("loginForm")
    .classList.add("hidden");

    document
    .getElementById("registerForm")
    .classList.remove("hidden");

}


function showLogin(){

    document
    .getElementById("registerForm")
    .classList.add("hidden");

    document
    .getElementById("loginForm")
    .classList.remove("hidden");

}


/* USER */

async function loadUser(){

    const response =
        await fetch("/api/me");


    if(!response.ok)
        return;


    const user =
        await response.json();


    document
    .getElementById("authPage")
    .classList.add("hidden");


    document
    .getElementById("mainPage")
    .classList.remove("hidden");


    document
    .getElementById("userName")
    .innerText = user.name;


    document
    .getElementById("profileName")
    .innerText = user.name;


    document
    .getElementById("profileEmail")
    .innerText = user.email;


    updateXP(
        user.xp,
        user.level
    );

}


/* LOGOUT */

async function logout(){

    await fetch(
        "/api/logout",
        {
            method:"POST"
        }
    );

    location.reload();

}


/* XP */

function updateXP(xp,level){

    document
    .getElementById("xp")
    .innerText = xp;


    document
    .getElementById("level")
    .innerText = level;


    document
    .getElementById("progressBar")
    .style.width =
        ((xp % 50) * 2) + "%";

}


async function addXP(){

    const response =
        await fetch(
            "/api/xp",
            {
                method:"POST",

                headers:{
                    "Content-Type":
                    "application/json"
                },

                body:JSON.stringify({
                    amount:10
                })
            }
        );


    if(!response.ok)
        return;


    const data =
        await response.json();


    updateXP(
        data.xp,
        data.level
    );

}


/* COURSES */

const tasks = {

    HTML:{
        title:"HTML topshirig‘i",
        text:"<h1> tegidan foydalanib sarlavha yarating."
    },

    CSS:{
        title:"CSS topshirig‘i",
        text:"color xususiyatidan foydalanib rangni o‘zgartiring."
    },

    JavaScript:{
        title:"JavaScript topshirig‘i",
        text:"alert() yordamida xabar chiqaring."
    },

    Python:{
        title:"Python topshirig‘i",
        text:"print() yordamida xabar chiqaring."
    }

};


let solved = false;


function selectCourse(course){

    document
    .getElementById("taskTitle")
    .innerText =
        tasks[course].title;


    document
    .getElementById("taskText")
    .innerText =
        tasks[course].text;


    document
    .getElementById("code")
    .value = "";


    document
    .getElementById("result")
    .innerText =
        "Kodingizni yozing.";


    solved = false;


    document
    .getElementById("practice")
    .scrollIntoView({
        behavior:"smooth"
    });

}


/* CHECK */

async function checkCode(){

    if(solved){

        document
        .getElementById("result")
        .innerText =
        "ℹ️ Bu topshiriq uchun XP allaqachon berilgan.";

        return;
    }


    const code =
        document
        .getElementById("code")
        .value
        .trim();


    if(!code){

        document
        .getElementById("result")
        .innerText =
        "❌ Kod yozing.";

        return;
    }


    const title =
        document
        .getElementById("taskTitle")
        .innerText;


    let correct = false;


    if(title.includes("HTML"))
        correct = code.includes("<h1>");

    else if(title.includes("CSS"))
        correct = code.includes("color");

    else if(title.includes("JavaScript"))
        correct = code.includes("alert");

    else if(title.includes("Python"))
        correct = code.includes("print");


    if(correct){

        solved = true;

        document
        .getElementById("result")
        .innerText =
        "✅ To‘g‘ri! +10 XP 🎉";

        await addXP();

    }

    else{

        document
        .getElementById("result")
        .innerText =
        "❌ Hali to‘g‘ri emas.";

    }

}


/* AI */

function sendAI(){

    const input =
        document
        .getElementById("aiInput");


    const text =
        input.value.trim();


    if(!text)
        return;


    const chat =
        document
        .getElementById("chat");


    const user =
        document.createElement("div");


    user.className =
        "message user";


    user.innerText = text;


    chat.appendChild(user);


    input.value = "";


    setTimeout(() => {

        const ai =
            document.createElement("div");


        ai.className =
            "message ai";


        const lower =
            text.toLowerCase();


        if(lower.includes("html")){

            ai.innerText =
            "🌐 HTML web sahifaning tuzilishini yaratadi.";

        }

        else if(lower.includes("css")){

            ai.innerText =
            "🎨 CSS sayt dizaynini boshqaradi.";

        }

        else if(lower.includes("python")){

            ai.innerText =
            "🐍 Python dasturlash tili. Masalan: print('Salom')";

        }

        else if(
            lower.includes("javascript") ||
            lower.includes("js")
        ){

            ai.innerText =
            "⚡ JavaScript saytga interaktivlik qo‘shadi.";

        }

        else{

            ai.innerText =
            "🤖 HTML, CSS, JavaScript yoki Python haqida savol bering.";

        }


        chat.appendChild(ai);


        chat.scrollTop =
            chat.scrollHeight;

    },500);

}


/* NAVIGATION */

function goCourses(){

    document
    .getElementById("courses")
    .scrollIntoView({
        behavior:"smooth"
    });

}


/* START */

loadUser();

</script>

</body>

</html>

`;


/* SEND WEBSITE */

app.get("/", (req, res) => {

    res.send(HTML);

});


/* START */

app.listen(PORT, () => {

    console.log(
        "CodeMentor AI: http://localhost:" + PORT
    );

});
