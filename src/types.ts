type Credentials = {
    email: string,
    password: string
}

type SignUpCredentials = Credentials & {
    name: string,
    organization: string,
    roles: string[]
}

type Response = {
    success: boolean,
    message: string,
    token?: string
}

enum Messages  {
    LOGIN_SUCCESSFULL,
    LOGIN_FAILED,
    SIGNUP_SUCCESSFUL,
    SIGNUP_FAILED,
    USER_NOT_FOUND,
    USER_ALREADY_EXISTS,
    CREDENTIALS_INVALID,
    ERROR_GENERATING_TOKEN,
    USER_DELETED_SUCCESSFULLY,
    ERROR_ESTABLISHING_DB_CONN,
    USER_ROLE_NOT_AUTHORIZED,
    USER_ROLE_AUTHORIZED
}

export {
    Credentials,
    SignUpCredentials,
    Response,
    Messages
}