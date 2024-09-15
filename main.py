# main.py

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from jose.exceptions import JWTError
import httpx

app = FastAPI()

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],  # Update this with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth0 configuration
AUTH0_DOMAIN = "dev-mazc2h57lknel3yr.uk.auth0.com"
API_AUDIENCE = "sspm"
ALGORITHMS = ["RS256"]

token_auth_scheme = HTTPBearer()

# Helper function to fetch Auth0 public key
async def get_auth0_public_key():
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
        jwks = resp.json()
        return jwks['keys'][0]

# Dependency to verify JWT token
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    try:
        public_key = await get_auth0_public_key()
        payload = jwt.decode(
            credentials.credentials,
            public_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/"
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# Unprotected route
@app.get("/api/public")
async def public_route():
    return {"message": "This is a public route"}

# Protected route
@app.get("/api/protected")
async def protected_route(payload: dict = Depends(verify_token)):
    return {"message": "This is a protected route", "user": payload.get("sub")}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)