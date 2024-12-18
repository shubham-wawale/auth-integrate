# My Auth Package

A reusable authentication middleware for Node.js applications using PostgreSQL and JWT.

## Installation

```bash
npm install my-auth-package
```
## Example Code

```bash
import { AuthService } from 'auth-integrate';

const connectionString = 'postgres://username:password@localhost:5432/mydb';
const jwtSecret = 'my-secure-jwt-secret';

const authService = new AuthService(connectionString, jwtSecret);

// Authenticate User
authService.login('test@example.com', 'password123')
  .then(response => console.log(response))
  .catch(err => console.error('Error:', err));

// Close database connection when done
authService.getDb()?.close();
```