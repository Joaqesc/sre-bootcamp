import mysql.connector
import hashlib
import jwt
import os


class Token:

    db_cnx = mysql.connector.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'user'),
        password=os.getenv('DB_PASSWORD', 'password'),
        database=os.getenv('DB_NAME', 'mysql')
    )

    def generate_token(self, request_username, request_password):

        db_cursor = self.db_cnx.cursor()
        db_cursor.execute("SELECT password,salt,role FROM users WHERE username = %s LIMIT 1", (request_username,))
        db_response = db_cursor.fetchone()
        db_cursor.close()
        self.db_cnx.close()

        if db_response:
            (db_password, salt, role) = db_response
            request_hash = hashlib.sha512((request_password + salt).encode('utf-8')).hexdigest()

            if request_hash == db_password:
                try:
                    payload = {
                        'role': role
                    }
                    return jwt.encode(
                        payload,
                        os.getenv('JWT_SECRET', 'secret'),
                        algorithm="HS256"
                    )
                except Exception as e:
                    return e
            else:
                return '403'
        else:
            return 'Invalid credentials'


class Restricted:
    jwt_secret = os.getenv('JWT_SECRET', 'secret')

    def access_data(self, authorization):

        try:
            jwt.decode(authorization, self.jwt_secret)
            return {"data": "You are under protected data"}
        except jwt.ExpiredSignatureError:
            return 'Signature expired.'
        except jwt.InvalidTokenError:
            return 'Invalid token.'
