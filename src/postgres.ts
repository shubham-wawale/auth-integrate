import pg from 'pg';
import { config } from './config.js';
const {Pool, Client} = pg;

class Database {

    private _pool: pg.Pool;

    constructor (connectionString: string) {
        this._pool = new Pool({
            connectionString: connectionString
        });
    }

    query (text: string, params: Array<any>) {
        return this._pool.query(text, params);
    }

    close() {
        return this._pool.end();
    }
}

export default Database;




