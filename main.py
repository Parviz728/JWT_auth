import datetime
import jwt
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer


app = FastAPI()

SECRET_KEY = "dba749b064fa8502475b7bd8b31b81d2cb20a34fbfee762ba4ba9c09093c799a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class PayLoad(BaseModel):
    username: str | None
    password: str | None

USERS_DATA = [
    {"username": "admin", "password": "adminpass"},
    {"username": "parviz", "password": "qwerty"},
    {"username": "umed", "password": "ytrewq"}
    ]

def create_jwt_token(data: dict):
    expire = datetime.datetime.now() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.setdefault("exp", expire)
    return {"access_token": jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)}

@app.post('/login')
async def authorize(payload: PayLoad):
    for user in USERS_DATA:
        if user.get("username") == payload.username and user.get("password") == payload.password:
            return create_jwt_token({"sub": payload.username})
    return HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Autheticate": "Bearer"})

@app.get('/protected_resource')
async def get_user_from_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub", HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Autheticate": "Bearer"}))
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return {"message": "Access granted to protected resource"}


