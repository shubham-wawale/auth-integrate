import { Credentials, Messages, SignUpCredentials } from "./types.js";
import Database from "./postgres.js";
import Query from "./query.js";

export class AuthService {

    private _connectionString: string;
    private _jwtSecret: string;
    private _db: Database | null;
    private _query: Query;

    constructor(connectionString:string, jwtSecret: string) {
        this._connectionString = connectionString;
        this._jwtSecret = jwtSecret;
        try{
            this._db = new Database(connectionString);
        } catch (error) {
            this._db = null;
        }
        if (!this._db) {
            throw new Error(Messages[Messages.ERROR_ESTABLISHING_DB_CONN]);
        }
        this._query = new Query(this._db, jwtSecret);
    }

    async login (email: string, password: string) {
        const credentials: Credentials = {
            email: email,
            password: password
        }  
        return this._query.selectUser(credentials);
    }

    async signup (name:string, email:string, password: string, organization: string, roles: string[]) {
        const credentials: SignUpCredentials = {
            name: name,
            email: email,
            password: password,
            organization: organization,
            roles: roles
        }
        return this._query.insertUser(credentials);
    }

    async removeAccount (email: string) {
        return this._query.deleteUser(email);
    }

    async authorize (token: string, role: string) {
        return this._query.verify(token, role);
    }

    getDb() {
        return this._db;
    }
}


