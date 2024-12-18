import { Credentials, SignUpCredentials, Response, Messages } from "./types.js";
import Database from "./postgres.js";
import jwt, { JsonWebTokenError, NotBeforeError, TokenExpiredError } from 'jsonwebtoken';
import { config } from "./config.js";
import bcrypt from "bcrypt";

class Query {

    private _db: Database;
    private _jwtSecret: Buffer<ArrayBuffer>;

    constructor(db: Database, jwtSecret: string) {
        this._db = db;
        this._jwtSecret = Buffer.from(jwtSecret, 'base64');
    }

    async selectUser(credentials: Credentials): Promise<Response> {

        let query = 'SELECT * FROM users WHERE email=$1';
        let response: Response = buildResponse(false, Messages.USER_NOT_FOUND);

        const result = await this._db.query(query, [
            credentials.email
        ]);
        if (result.rowCount != 1) {
            return response;
        }

        const user = result.rows[0];
        bcrypt.compare(credentials.password, user.password, function (err, result) {
            if (!result) {
                return buildResponse(false, Messages.CREDENTIALS_INVALID);
            }
        });

        const payload = {
            userId: user.id,
            email: user.email,
            org: user.organization,
            roles: user.roles
        }
        const _token = jwt.sign(
            payload,
            this._jwtSecret,
            { algorithm: 'HS256', expiresIn: '2d' }
        );
        if (_token != null) {
            response = buildResponse(true, Messages.LOGIN_SUCCESSFULL, _token);
        } else {
            response = buildResponse(false, Messages.ERROR_GENERATING_TOKEN);
        }

        return response;
    }

    async insertUser(credentials: SignUpCredentials) {
        const user = await this._db.query('SELECT * FROM users WHERE email=$1', [
            credentials.email
        ]);
        if (user.rowCount == 1) {
            return buildResponse(false, Messages.USER_ALREADY_EXISTS);
        }
        let query = 'INSERT INTO users (name, email, password, organization, roles) VALUES ($1, $2, $3, $4, $5)';
        let password: string = "";
        bcrypt.hash(credentials.password, 10, function (err, hash) {
            password = hash;
        });
        let values = [
            credentials.name,
            credentials.email,
            password,
            credentials.organization,
            credentials.roles
        ]
        const result = await this._db.query(query, values);
        let response: Response = buildResponse(false, Messages.SIGNUP_FAILED);
        if (result.rowCount == 1) {
            response = buildResponse(true, Messages.SIGNUP_SUCCESSFUL);
        }
        return response;
    }

    async deleteUser(email: string) {
        let query = 'DELETE FROM users WHERE email=$1';
        let response = buildResponse(false, Messages.USER_NOT_FOUND);
        const result = await this._db.query(query, [
            email
        ]);
        if (result.rowCount == 1) {
            response = buildResponse(true, Messages.USER_DELETED_SUCCESSFULLY);
        }
        return response;
    }

    async verify(token: string, role: string): Promise<Response> {
        return new Promise((resolve, reject)=>{
            jwt.verify(token, this._jwtSecret, (err, user: any) => {
                if (err) {
                    return resolve(
                        buildResponse(
                            false,
                            `${err.name}: ${err.message}`
                        )
                    );
                }
    
                if (user != null) {
                    const allowed = user.roles.includes(role);
                    if (!allowed) {
                        return resolve(
                            buildResponse(
                                false,
                                Messages.USER_ROLE_NOT_AUTHORIZED
                            )
                        );
                    }
                }
    
                resolve(
                    buildResponse(
                        true,
                        Messages.USER_ROLE_AUTHORIZED
                    )
                );
        
            })
        });
    }

}

const buildResponse = (_success: boolean, _message: Messages | string, _token?: string): Response => {
    const message = typeof _message === "string" ? _message : Messages[_message];
    if (_token != null) {
        return {
            success: _success,
            message: message,
            token: _token
        }
    }
    return {
        success: _success,
        message: message
    }
}

export default Query;