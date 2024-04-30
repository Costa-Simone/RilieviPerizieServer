import _http from "http";
import _https from "https";
import _url from "url";
import _fs from "fs";
import _express from "express";
import _dotenv from "dotenv";
import _cors from "cors";
import _fileUpload from "express-fileupload";
import _cloudinary, { UploadApiResponse } from 'cloudinary';
import _streamifier from "streamifier";
import _axios from "axios";
import _nodemailer from "nodemailer";
const _nodemailer = require("nodemailer")
import _bcrypt from "bcryptjs";
import _jwt from "jsonwebtoken";

// Lettura delle password e parametri fondamentali
_dotenv.config({ "path": ".env" });

// Configurazione Cloudinary
_cloudinary.v2.config({
    cloud_name: process.env.cloud_name,
    api_key: process.env.api_key,
    api_secret: process.env.api_secret
});

// Variabili relative a MongoDB ed Express
import { MongoClient, ObjectId } from "mongodb";
const DBNAME = process.env.DBNAME;
const connectionString: string = process.env.connectionStringAtlas as any
const app = _express();

// Creazione ed avvio del server https, a questo server occorre passare le chiavi RSA (pubblica e privata)
// app è il router di Express, si occupa di tutta la gestione delle richieste https
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT as string);
let paginaErrore;
const PRIVATE_KEY = _fs.readFileSync("./keys/privateKey.pem", "utf8");
const CERTIFICATE = _fs.readFileSync("./keys/certificate.crt", "utf8");
const SIMMETRIC_KEY = _fs.readFileSync("./keys/encryptionKey.txt", "utf8")
const CREDENTIALS = { "key": PRIVATE_KEY, "cert": CERTIFICATE };
const server = _http.createServer(app)

const auth = {
    "user": process.env.gmailUser,
    "pass": process.env.gmailPassword,
}
const transporter = _nodemailer.createTransport({
    "service": "gmail",
    "auth": auth
});
let message = _fs.readFileSync("./message.html", "utf8");

server.listen(HTTPS_PORT, () => {
    init()

    console.log(`Il Server è in ascolto sulla porta ${HTTPS_PORT}`);
});

function init() {
    _fs.readFile("./static/error.html", function (err, data) {
        if (err) {
            paginaErrore = "<h1>Risorsa non trovata</h1>";
        }
        else {
            paginaErrore = data.toString();
        }
    });
}

////
// Socket
////

var WebSocketServer = require('websocket').server;

var wsServer = new WebSocketServer({
    httpServer: server,
    // You should not use autoAcceptConnections for production
    // applications, as it defeats all standard cross-origin protection
    // facilities built into the protocol and the browser.  You should
    // *always* verify the connection's origin and decide whether or not
    // to accept it.
    autoAcceptConnections: false
});

function originIsAllowed(origin) {
    // put logic here to detect whether the specified origin is allowed.
    return true;
}

wsServer.on('request', function(request) {
    let users = []
    let admin

    if (!originIsAllowed(request.origin)) {
      // Make sure we only accept requests from an allowed origin
      request.reject();
      console.log((new Date()) + ' Connection from origin ' + request.origin + ' rejected.');
      return;
    }
    
    var connection = request.accept('echo-protocol', request.origin);

    connection.on('message', function(message) {
        if (message.type === 'utf8') {
            console.log('Received Message: ' + message.utf8Data);
            let msg = JSON.parse(message.utf8Data)
            
            if(msg.status == "online") {
                const client = new MongoClient(connectionString)
                client.connect()
                let collection = client.db(DBNAME).collection("users")
                let rq = collection.updateOne({username: msg.user}, {$set: {status: msg.status}})
                rq.catch((err) => { console.log("Errore esecuzione query " + err.message) })
                rq.then(data => {
                    if(msg.user == "admin") {
                        admin = connection
                    }

                    console.log("Utente " + msg.user + " è " + msg.status)
                    users.push({user: msg.user, address: connection.remoteAddress})

                    if(admin != null) {
                        admin.send(JSON.stringify("update"))
                    }
                })
                rq.finally(() => client.close())
            }
        }
        else if (message.type === 'binary') {
            console.log('Received Binary Message of ' + message.binaryData.length + ' bytes');
            connection.send(message.binaryData);
        }
    });
    connection.on('close', function(reasonCode, description) {
        console.log((new Date()) + ' Peer ' + connection.remoteAddress + ' disconnected.');
        let user = users.find((u) => u.address == connection.remoteAddress)

        const client = new MongoClient(connectionString)
        client.connect()
        let collection = client.db(DBNAME).collection("users")
        let rq = collection.updateOne({username: user.user}, {$set: {status: "offline"}})
        rq.catch((err) => { console.log("Errore esecuzione query " + err.message) })
        rq.then(data => {
            console.log("Utente " + user.user + " è offline")
            users.splice(users.indexOf(user), 1)
            connection.send("update")
        })
        rq.finally(() => client.close())
    });
});

////
// Routes middleware
////

// 1. Request log
app.use("/", (req: any, res: any, next: any) => {
    console.log(`-----> ${req.method}: ${req.originalUrl}`);
    next();
});

// 2. Gestione delle risorse statiche
// .static() è un metodo di express che ha già implementata la firma di sopra. Se trova il file fa la send() altrimenti fa la next()
app.use("/", _express.static("./static"));

// 3. Lettura dei parametri POST di req["body"] (bodyParser)
// .json() intercetta solo i parametri passati in json nel body della http request
app.use("/", _express.json({ "limit": "50mb" }));
// .urlencoded() intercetta solo i parametri passati in urlencoded nel body della http request
app.use("/", _express.urlencoded({ "limit": "50mb", "extended": true }));

// 4. Aggancio dei parametri del FormData e dei parametri scalari passati dentro il FormData
// Dimensione massima del file = 10 MB
app.use("/", _fileUpload({ "limits": { "fileSize": (10 * 1024 * 1024) } }));

// 5. Log dei parametri GET, POST, PUT, PATCH, DELETE
app.use("/", (req: any, res: any, next: any) => {
    if (Object.keys(req["query"]).length > 0) {
        console.log(`       ${JSON.stringify(req["query"])}`);
    }
    if (Object.keys(req["body"]).length > 0) {
        console.log(`       ${JSON.stringify(req["body"])}`);
    }
    next();
});

// 6. Controllo degli accessi tramite CORS
// Procedura che lascia passare tutto, accetta tutte le richieste

const corsOptions = {
    origin: function (origin, callback) {
        return callback(null, true);
    },
    credentials: true
};
app.use("/", _cors(corsOptions));

app.post("/api/newMail", async (req, res, next) => {
    let password = generatePassword(8, { lowercase: true, uppercase: true, numbers: true, symbols: false })
    console.log(password)
    let user = req.body.user

    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("users")
    let request = collection.findOne({ username: user })
    request.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    request.then(data => {
        let rq = collection.updateOne({ _id: new ObjectId(data._id) }, { $set: { password: _bcrypt.hashSync(password, 10), firstTime: true } })
        rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
        rq.then(response => {
            message = message.replace("__password", password);

            let mailOptions = {
                "from": auth.user,
                "to": data.email,
                "subject": "Cambio password",
                //"html": req["body"].message,
                "html": message,
            }
            
            transporter.sendMail(mailOptions, (err, info) => {
                console.log(info);
                if (err) {
                    res.status(500).send(`Errore invio mail:\n${err.message}`);
                }
                else {
                    message = message.replace(password, "__password");
                    res.send("Ok");
                }
            });
        })
        rq.finally(() => client.close())
    })
});

//8 LOGIN
app.post("/api/login", async (req, res, next) => {
    let user = req.body.username
    let pass = req.body.password

    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("users")
    let reg = new RegExp(`^${user}$`, "i")

    let rq = collection.findOne({ "username": reg })
    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data: any) => {
        if (!data) {
            res.status(401).send("Username non trovato")
        }
        _bcrypt.compare(pass, data["password"], (err, result) => {
            if (err) {
                res.status(500).send("bcrypt compare error" + err.message)
            }
            else {
                if (!result) {
                    res.status(401).send("Password errata")
                }
                else {
                    let token = creaToken(data)
                    res.setHeader("authorization", token)
                    //! Fa si che la header authorization venga restituita al client
                    res.setHeader("access-control-expose-headers", "authorization")

                    if (data["firstTime"]) {
                        res.send({ "ris": "firstTime" })
                    } else {
                        res.send({ "ris": "ok" })
                    }
                }
            }
        })
    })
    rq.finally(() => client.close())
})

function creaToken(user) {
    let currentDate = Math.floor(new Date().getTime() / 1000)
    let payLoad = {
        "_id": user._id,
        "username": user.username,
        "admin": user["admin"],
        "iat": user.iat || currentDate,
        "exp": currentDate + parseInt(process.env.TOKEN_DURATION!)
    }

    return _jwt.sign(payLoad, SIMMETRIC_KEY)
}

// 10. Controllo del token
app.use("/api/", (req, res, next) => {
    if (req["body"]["skipCheckToken"]) {
        next()
    } else {
        if (!req.headers["authorization"]) {
            res.status(403).send("Token mancante")
        }
        else {
            let token = req.headers["authorization"]
            _jwt.verify(token, SIMMETRIC_KEY, (err, payload) => {
                if (err) {
                    res.status(403).send("Token corrotto " + err)
                }
                else {
                    let token = creaToken(payload)
                    res.setHeader("authorization", token)
                    //! Fa si che la header authorization venga restituita al client
                    res.setHeader("access-control-expose-headers", "authorization")
                    req["payload"] = payload
                    next()
                }
            })
        }
    }
})

////
// Routes finali di risposta al client
////

app.post("/api/cambiaPassword", async (req, res, next) => {
    let user = req.body.user
    let password = req.body.password
    let firstTime = req.body.firstTime

    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("users")
    let request = await collection.findOne({ username: user })

    if (firstTime) {
        firstTime = !firstTime
    }

    let rq = collection.updateOne({ _id: new ObjectId(request._id) }, { $set: { password: _bcrypt.hashSync(password, 10), firstTime: firstTime } })

    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data) => {
        res.send(data)
    })
    rq.finally(() => client.close())
})

function generatePassword(length: number, options?: {
    lowercase?: boolean;
    uppercase?: boolean;
    numbers?: boolean;
    symbols?: boolean;
}): string {
    // Define character sets
    const lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
    const uppercaseChars = lowercaseChars.toUpperCase();
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()-_=+[]{};:,<.>/?';

    // Build allowed characters string
    let allowedChars = '';
    if (options?.lowercase !== false) allowedChars += lowercaseChars;
    if (options?.uppercase !== false) allowedChars += uppercaseChars;
    if (options?.numbers !== false) allowedChars += numbers;
    if (options?.symbols !== false) allowedChars += symbols;

    // Check for at least one character set
    if (!allowedChars) {
        throw new Error('Password must include at least one character set');
    }

    // Generate random password
    let password = '';
    for (let i = 0; i < length; i++) {
        password += allowedChars.charAt(Math.floor(Math.random() * allowedChars.length));
    }

    return password;
}

app.get("/api/users", async (req, res, next) => {
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("users")
    let rq = collection.find({}, { projection: { _id: 1, username: 1, admin: 1, email: 1, status: 1 } }).toArray()
    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data) => {
        res.send(data)
    })
    rq.finally(() => client.close())
})

app.post("/api/addUser", async (req, res, next) => {
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("users")
    let user = req.body
    user["password"] = _bcrypt.hashSync(user["password"], 10)
    let rq = collection.insertOne(user)
    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data) => {
        res.send(data)
    })
    rq.finally(() => client.close())
})

app.post("/api/editUser/:id", async (req, res, next) => {
    let id = req.params.id
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("users")
    let user = req.body
    let rq = collection.updateOne({ _id: new ObjectId(id) }, { $set: user })
    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data) => {
        res.send(data)
    })
    rq.finally(() => client.close())
})

app.post("/api/deleteUser/:id", async (req, res, next) => {
    let id = req.params.id
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("users")
    let rq = collection.deleteOne({ _id: new ObjectId(id) })
    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data) => {
        res.send(data)
    })
    rq.finally(() => client.close())
})

app.get("/api/perizie", async (req, res, next) => {
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("perizie")
    let rq = collection.find().toArray()
    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data) => {
        res.send(data)
    })
    rq.finally(() => client.close())
})

app.get("/api/perizieByUser", async (req, res, next) => {
    let user = req["payload"]["username"]
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("users")
    let rq = collection.findOne({ username: user }, { projection: { _id: 1, username: 1, admin: 1, email: 1 } })
    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data) => {
        let coll = client.db(DBNAME).collection("perizie")
        let request = coll.find({ operator: data["_id"].toString() }).toArray()
        request.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message); client.close() })
        request.then((perizie) => {
            let req = coll.findOne({ title: "Vallauri" })
            req.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message); client.close() })
            req.then(aus => {
                perizie.push(aus)
                res.send(perizie)
            })
        })
    })
})

app.post("/api/editPerizia/:id", async (req, res, next) => {
    let id = req.params.id
    let perizia = req.body
    let aus = []

    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("perizie")
    let request = collection.findOne({ _id: new ObjectId(id) })
    request.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    request.then(data => {
        let count = data.photos.length
        const vettUguali = (v1: any[], v2: any[]) => v1.every((c) => v2.includes(c)) && v1.length == v2.length;

        if (vettUguali(perizia.photos, data.photos)) {
            let rq = collection.updateOne({ _id: new ObjectId(id) }, { $set: perizia });
            rq.then((data) => res.send(data));
            rq.catch((err) => res.status(500).send(`Errore esecuzione query: ${err}`));
            rq.finally(() => client.close());
        } else {
            if (count > 0) {
                if (perizia.photos.length > 0) {
                    perizia.photos.forEach((photo) => {
                        if (!photo.includes("RilieviPerizie")) {
                            _cloudinary.v2.uploader.upload(photo, { "folder": "RilieviPerizie" })
                                .catch((err) => {
                                    res.status(500).send(`Error while uploading file on Cloudinary: ${err}`);
                                })
                                .then(async function (response: UploadApiResponse) {
                                    aus.push(response.secure_url)

                                    if (aus.length == perizia.photos.length) {
                                        perizia.photos = aus
                                        let rq = collection.updateOne({ _id: new ObjectId(id) }, { $set: perizia });
                                        rq.then((data) => res.send(data));
                                        rq.catch((err) => res.status(500).send(`Errore esecuzione query: ${err}`));
                                        rq.finally(() => client.close());
                                    }
                                });
                        } else {
                            aus.push(photo)

                            if (aus.length == perizia.photos.length) {
                                perizia.photos = aus
                                let rq = collection.updateOne({ _id: new ObjectId(id) }, { $set: perizia });
                                rq.then((data) => res.send(data));
                                rq.catch((err) => res.status(500).send(`Errore esecuzione query: ${err}`));
                                rq.finally(() => client.close());
                            }
                        }
                    })
                } else {
                    let rq = collection.updateOne({ _id: new ObjectId(id) }, { $set: perizia });
                    rq.then((data) => res.send(data));
                    rq.catch((err) => res.status(500).send(`Errore esecuzione query: ${err}`));
                    rq.finally(() => client.close());
                }
            } else {
                perizia.photos.forEach((photo) => {
                    _cloudinary.v2.uploader.upload(photo, { "folder": "RilieviPerizie" })
                        .catch((err) => {
                            res.status(500).send(`Error while uploading file on Cloudinary: ${err}`);
                        })
                        .then(async function (response: UploadApiResponse) {
                            aus.push(response.secure_url)

                            if (aus.length == perizia.photos.length) {
                                perizia.photos = aus
                                const client = new MongoClient(connectionString);
                                await client.connect();
                                let collection = client.db(DBNAME).collection("perizie");
                                let rq = collection.updateOne({ _id: new ObjectId(id) }, { $set: perizia });
                                rq.then((data) => res.send(data));
                                rq.catch((err) => res.status(500).send(`Errore esecuzione query: ${err}`));
                                rq.finally(() => client.close());
                            }
                        });
                })
            }
        }
    })
})

app.post("/api/addPerizia", async (req, res, next) => {
    let newPerizia: any = req["body"];
    let aus = []
    // _cloudinary.v2.uploader.destroy()

    if (newPerizia.photos.length > 0) {
        newPerizia.photos.forEach((photo) => {
            _cloudinary.v2.uploader.upload(photo, { "folder": "RilieviPerizie" })
                .catch((err) => {
                    res.status(500).send(`Error while uploading file on Cloudinary: ${err}`);
                })
                .then(async function (response: UploadApiResponse) {
                    // IMPORTANTE FARE = {}
                    aus.push(response.secure_url)
                    // newContact["picture"] = {};
                    // newContact["picture"]["large"] = response.secure_url;
                    // newContact["picture"]["medium"] = response.secure_url;
                    // newContact["picture"]["thumbnail"] = response.secure_url;
                    if (aus.length == newPerizia.photos.length) {
                        newPerizia.photos = aus
                        const client = new MongoClient(connectionString);
                        await client.connect();
                        let collection = client.db(DBNAME).collection("perizie");
                        let rq = collection.insertOne(newPerizia);
                        rq.then((data) => res.send(data));
                        rq.catch((err) => res.status(500).send(`Errore esecuzione query: ${err}`));
                        rq.finally(() => client.close());
                    }
                });
        })
    } else {
        const client = new MongoClient(connectionString);
        await client.connect();
        let collection = client.db(DBNAME).collection("perizie");
        let rq = collection.insertOne(newPerizia);
        rq.then((data) => res.send(data));
        rq.catch((err) => res.status(500).send(`Errore esecuzione query: ${err}`));
        rq.finally(() => client.close());
    }
});

app.delete("/api/deletePerizia/:id", async (req, res, next) => {
    let id = req.params.id
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("perizie")
    let rq = collection.deleteOne({ _id: new ObjectId(id) })
    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data) => {
        res.send(data)
    })
    rq.finally(() => client.close())
})

////
// Default route e gestione degli errori
////

app.use("/", (req, res, next) => {
    res.status(404);
    if (req.originalUrl.startsWith("/api/")) {
        res.send("Api non disponibile");
    }
    else {
        res.send(paginaErrore);
    }
});


app.use("/", (err, req, res, next) => {
    console.log("************* SERVER ERROR ***************\n", err.stack);
    res.status(500).send(err.message);
});
