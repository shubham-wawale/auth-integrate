import Query from '../src/query'
import Database from '../src/postgres'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import { Messages, SignUpCredentials } from '../src/types'
import { QueryResult, QueryResultRow } from 'pg'

jest.mock('../src/postgres')
jest.mock('jsonwebtoken')
jest.mock('bcrypt')

function mockQueryResult<T extends QueryResultRow>(rows: T[], command: string = 'SELECT'): QueryResult<T> {
    return {
        command,
        rowCount: rows.length,
        oid: 0,
        fields: [],
        rows
    };
}

describe('Query Class', () => {
    let query: Query;
    let mockDb: jest.Mocked<Database>;
    let mockData: any[]
    const jwtSecret = Buffer.from('mockSecret').toString('base64')

    beforeAll(() => {
        mockDb = {
            query: jest.fn()
        } as unknown as jest.Mocked<Database>;
        query = new Query(mockDb, jwtSecret);
        mockData = [
            {
                name: 'test',
                email: 'test@example.com',
                password: 'hashed-password',
                organization: 'org1',
                roles: ['admin']
            }
        ]
    })

    beforeEach(() => {
        jest.clearAllMocks();
    })

    describe('selectUser()', () => {
        it('should return success when user is found and password matches', async () => {

            mockDb.query.mockResolvedValueOnce(mockQueryResult(
                mockData,
                'SELECT'
            ));
            (bcrypt.compare as jest.Mock).mockResolvedValueOnce(true);
            (jwt.sign as jest.Mock).mockReturnValue('mock-jwt-token')

            const res = await query.selectUser({
                email: 'test@example.com',
                password: 'correct-password',
            })
            expect(res.success).toBe(true);
            expect(res.message).toBe(Messages[Messages.LOGIN_SUCCESSFULL])
            expect(res.token).toBe('mock-jwt-token')
        })
        it('should return error when user not found', async () => {
            mockDb.query.mockResolvedValueOnce(mockQueryResult([], 'SELECT'))
            const res = await query.selectUser({
                email: 'test@example.com',
                password: 'correct-password',
            })
            expect(res.success).toBe(false);
            expect(res.message).toBe(Messages[Messages.USER_NOT_FOUND])
        })
        it('should return error when password does not match', async () => {
            mockDb.query.mockResolvedValueOnce(mockQueryResult(
                mockData,
                'SELECT'
            ));
            (bcrypt.compare as jest.Mock).mockResolvedValueOnce(false)
            const res = await query.selectUser({
                email: 'test@example.com',
                password: 'hashed-password',
            })
            expect(res.success).toBe(false)
            expect(res.message).toBe(Messages[Messages.CREDENTIALS_INVALID])
        })
    })

    describe('insertUser()', () => {
        it('should return error when user already exists', async () => {
            mockDb.query.mockResolvedValueOnce(mockQueryResult(
                mockData,
                'SELECT'
            ))
            const res = await query.insertUser(mockData[0])
            expect(res.success).toBe(false)
            expect(res.message).toBe(Messages[Messages.USER_ALREADY_EXISTS])

        })
        it('should return error when sigup fails from the database', async () => {
            mockDb.query.mockResolvedValueOnce(mockQueryResult(
                [],
                'SELECT'
            ))
            mockDb.query.mockResolvedValueOnce(mockQueryResult(
                [],
                'INSERT'
            ))
            const res = await query.insertUser(mockData[0])
            expect(res.success).toBe(false)
            expect(res.message).toBe(Messages[Messages.SIGNUP_FAILED])
        })
        it('should return success when user is new and credentials are complete', async () => {
            mockDb.query.mockResolvedValueOnce(mockQueryResult(
                [],
                'SELECT'
            ))
            mockDb.query.mockResolvedValueOnce(mockQueryResult(
                mockData,
                'INSERT'
            ))
            const res = await query.insertUser(mockData[0])
            expect(res.success).toBe(true)
            expect(res.message).toBe(Messages[Messages.SIGNUP_SUCCESSFUL])
        })
    })

    describe('deleteUser()', () => {
        it('should return error if user does not exist', async () => {
            mockDb.query.mockResolvedValueOnce(mockQueryResult(
                [],
                'DELETE'
            ))
            const res = await query.deleteUser(mockData[0].email)
            expect(res.success).toBe(false)
            expect(res.message).toBe(Messages[Messages.USER_NOT_FOUND])
        })
        it('should return success when user deleted successfully', async () => {
            mockDb.query.mockResolvedValueOnce(mockQueryResult(
                mockData,
                'DELETE'
            ))
            const res = await query.deleteUser(mockData[0].email)
            expect(res.success).toBe(true)
            expect(res.message).toBe(Messages[Messages.USER_DELETED_SUCCESSFULLY])
        })
    })

    describe('verify()', () => {
        it('should error if jwt.verify fails', async () => {
            (jwt.verify as jest.Mock).mockImplementation((_token, _secret, cb) => {
                cb(new Error('invalid token'), null)
            })
            const res = await query.verify('mock-jwt-token', 'admin')
            expect(res.success).toBe(false)
            expect(res.message).toBe('Error: invalid token')
        })
        it('should error if user role is not authorized', async () => {
            (jwt.verify as jest.Mock).mockImplementation((_token, _secret, cb) => {
                cb(null, mockData[0])
            })
            const res = await query.verify('mock-jwt-token', 'customer')
            expect(res.success).toBe(false)
            expect(res.message).toBe(Messages[Messages.USER_ROLE_NOT_AUTHORIZED])
        })
        it('should success if user has the right authorizations', async () => {
            (jwt.verify as jest.Mock).mockImplementation((_token, _secret, cb) => {
                cb(null, mockData[0])
            })
            const res = await query.verify('mock-jwt-token', 'admin')
            expect(res.success).toBe(true)
            expect(res.message).toBe(Messages[Messages.USER_ROLE_AUTHORIZED])
        })
    })

})

