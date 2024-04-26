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
// import _nodemailer from "nodemailer";
const _nodemailer = require("nodemailer")
import _bcrypt from "bcryptjs";
import _jwt from "jsonwebtoken";
import { google } from "googleapis"

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
const connectionString:string = process.env.connectionStringAtlas as any
const app = _express();

// Creazione ed avvio del server https, a questo server occorre passare le chiavi RSA (pubblica e privata)
// app è il router di Express, si occupa di tutta la gestione delle richieste https
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT as string);
let paginaErrore;
const PRIVATE_KEY = _fs.readFileSync("./keys/privateKey.pem", "utf8");
const CERTIFICATE = _fs.readFileSync("./keys/certificate.crt", "utf8");
const SIMMETRIC_KEY = _fs.readFileSync("./keys/encryptionKey.txt", "utf8")
const CREDENTIALS = { "key": PRIVATE_KEY, "cert": CERTIFICATE };
const https_server = _https.createServer(CREDENTIALS, app);
const server = _http.createServer(app)

// Il secondo parametro facoltativo ipAddress consente di mettere il server in ascolto su una delle interfacce della macchina, se non lo metto viene messo in ascolto su tutte le interfacce (3 --> loopback e 2 di rete)
// https_server.listen(HTTPS_PORT, () => {
//     init();
//     console.log(`Server HTTPS in ascolto sulla porta ${HTTPS_PORT}
//     `);
// });
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
    origin: function(origin, callback) {
    return callback(null, true);
    },
    credentials: true
   };
app.use("/", _cors(corsOptions));

// const whitelist = [
//     "http://corneanugeorgealexandru-crudserver.onrender.com",	// porta 80 (default)
//     "https://corneanugeorgealexandru-crudserver.onrender.com",	// porta 443 (default)
//     "http://localhost:3000",
//     "https://localhost:3001",
//     "http://localhost:4200",
//     "http://localhost:8100",
//     "https://192.168.1.27",
//     "*" // server angular
// ];
// // Procedura che utilizza la whitelist, accetta solo le richieste presenti nella whitelist
// const corsOptions = {
//     origin: function (origin, callback) {
//         if (!origin) // browser direct call
//             return callback(null, true);
//         if (whitelist.indexOf(origin) === -1) {
//             var msg = "The CORS policy for this site does not allow access from the specified Origin."
//             return callback(new Error(msg), false);
//         }
//         else
//             return callback(null, true);
//     },
//     credentials: true
// };
// app.use("/", _cors(corsOptions));

// 7. Configurazione di nodemailer
/*const auth = {
    "user": process.env.gmailUser,
    "pass": process.env.gmailPassword,
}
const transporter = _nodemailer.createTransport({
    "service": "gmail",
    "auth": auth
});
let message = _fs.readFileSync("./message.html", "utf8");*/

// 7b. Configurazione di nodemailer con oAuth2
const o_Auth2 = JSON.parse(process.env.oAuthCredential as any)
const OAuth2 = google.auth.OAuth2; // Oggetto OAuth2
const OAuth2Client = new OAuth2(
    o_Auth2["client_id"],
    o_Auth2["client_secret"]
);
OAuth2Client.setCredentials({
    refresh_token: o_Auth2.refresh_token,
});

let message = _fs.readFileSync("./message.html", "utf8");

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
    rq.then((data:any) => {
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
                    
                    if(data["firstTime"]) {
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

// 9. Controllo accesso con Google
app.post("/api/googleLogin", async (req, res, next) => {
    if (!req.headers["authorization"]) {
        res.status(403).send("Token mancante")
    } else {
        let token = req.headers["authorization"]
        let payload = _jwt.decode(token)
        let username = payload["email"]

        const client = new MongoClient(connectionString)
        await client.connect()
        const collection = client.db(DBNAME).collection("mail")
        let reg = new RegExp(`^${username}$`, "i")

        let rq = collection.findOne({ "username": reg }, { "projection": { "username": 1, "password": 1 } })
        rq.then(dbUser => {
            if (!dbUser) {
                res.status(403).send("Utente non autorizzato all'accesso")
            } else {
                let token = creaToken(dbUser)

                res.setHeader("authorization", token)
                //! Fa si che la header authorization venga restituita al client
                res.setHeader("access-control-expose-headers", "authorization")
                res.send({ "ris": "ok" })
            }
        })
    }
})

// 10. Controllo del token
app.use("/api/", (req, res, next) => {
    if(req["body"]["skipCheckToken"]) {
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
    let request = await collection.findOne({username: user})

    if(firstTime) {
        firstTime = !firstTime
    }
    
    let rq = collection.updateOne({_id: new ObjectId(request._id)}, {$set: {password: _bcrypt.hashSync(password, 10), firstTime: firstTime}})

    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data) => {
        res.send(data)
    })
    rq.finally(() => client.close())
})

app.get("/api/users", async (req, res, next) => {
    const client = new MongoClient(connectionString)
    await client.connect()
    const collection = client.db(DBNAME).collection("users")
    let rq = collection.find({}, {projection: {_id: 1, username: 1, admin: 1, email: 1}}).toArray()
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
    let rq = collection.updateOne({_id: new ObjectId(id)}, {$set: user})
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
    let rq = collection.deleteOne({_id: new ObjectId(id)})
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
    let rq = collection.findOne({username: user}, {projection: {_id: 1, username: 1, admin: 1, email: 1}})
    rq.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    rq.then((data) => {
        let coll = client.db(DBNAME).collection("perizie")
        let request = coll.find({operator: data["_id"].toString()}).toArray()
        request.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message); client.close()})
        request.then((perizie) => {
            let req = coll.findOne({title: "Vallauri"})
            req.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message); client.close()})
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
    let request = collection.findOne({_id: new ObjectId(id)})
    request.catch((err) => { res.status(500).send("Errore esecuzione query " + err.message) })
    request.then(data => {
        let count = data.photos.length
        const vettUguali = (v1: any[], v2: any[]) => v1.every((c) => v2.includes(c)) && v1.length == v2.length;

        if(vettUguali(perizia.photos, data.photos)) {
            let rq = collection.updateOne({_id: new ObjectId(id)}, {$set: perizia});
            rq.then((data) => res.send(data));
            rq.catch((err) => res.status(500).send(`Errore esecuzione query: ${err}`));
            rq.finally(() => client.close());
        } else {
            if(count > 0) {
                if(perizia.photos.length > 0) {
                    perizia.photos.forEach((photo) => {
                        if(!photo.includes("RilieviPerizie")) {
                            _cloudinary.v2.uploader.upload(photo, { "folder": "RilieviPerizie" })
                            .catch((err) => {
                                res.status(500).send(`Error while uploading file on Cloudinary: ${err}`);
                            })
                            .then(async function (response: UploadApiResponse) {
                                aus.push(response.secure_url)
        
                                if(aus.length == perizia.photos.length) {
                                    perizia.photos = aus
                                    let rq = collection.updateOne({_id: new ObjectId(id)}, {$set: perizia});
                                    rq.then((data) => res.send(data));
                                    rq.catch((err) => res.status(500).send(`Errore esecuzione query: ${err}`));
                                    rq.finally(() => client.close());
                                }
                            });
                        } else {
                            aus.push(photo)
    
                            if(aus.length == perizia.photos.length) {
                                perizia.photos = aus
                                let rq = collection.updateOne({_id: new ObjectId(id)}, {$set: perizia});
                                rq.then((data) => res.send(data));
                                rq.catch((err) => res.status(500).send(`Errore esecuzione query: ${err}`));
                                rq.finally(() => client.close());
                            }
                        }
                    })
                } else {
                    let rq = collection.updateOne({_id: new ObjectId(id)}, {$set: perizia});
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
    
                        if(aus.length == perizia.photos.length) {
                            perizia.photos = aus
                            const client = new MongoClient(connectionString);
                            await client.connect();
                            let collection = client.db(DBNAME).collection("perizie");
                            let rq = collection.updateOne({_id: new ObjectId(id)}, {$set: perizia});
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
    
    if(newPerizia.photos.length > 0) {
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
                if(aus.length == newPerizia.photos.length) {
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
    let rq = collection.deleteOne({_id: new ObjectId(id)})
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
