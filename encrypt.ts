import bcrypt from "bcryptjs" // + @types
import {MongoClient, ObjectId}  from "mongodb";
import dotenv from "dotenv";
dotenv.config({ path: ".env" });

const CONNECTION_STRING:string = process.env.connectionStringAtlas!;
const DBNAME = process.env.DBNAME;

const client = new MongoClient(CONNECTION_STRING);
let promise = client.connect();

promise.catch(err => console.log(`Errore di connessione al DataBase: ${err}`))
promise.then(() => {
    let collection = client.db(DBNAME).collection("users");
    let rq = collection.find().toArray();

    rq.catch(err => {
        console.log(`Errore lettura record: ${err}`)
        client.close()
    })

    rq.then(data => {
        let promises:Promise<any>[] = []

        for(let user of data) {
            let regex = new RegExp("^\\$2[aby]\\$10\\$.{53}$") // regex per controllo presenza pwd cryptata (sicurezza 10)

            if(!regex.test(user["password"])) {
                let id = new ObjectId(user["_id"])
                let newPassword = bcrypt.hashSync(user["password"], 10) // cripta la password, creando un has
                console.log(user["password"])
                console.log(newPassword)
                console.log(bcrypt.hashSync("admin", 10))
                let promise = client.db(DBNAME).collection("users").updateOne({_id: id}, {$set: {password: newPassword}})

                promises.push(promise)
            }
        }

        Promise.all(promises).catch(err => console.log(`Errore nell'aggiornamento delle password: ${err}`)).then(results => {
            console.log("Password aggiornate correttamente: " + promises.length)
        }).finally(() => client.close())
    })
})
