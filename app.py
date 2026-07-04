from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError

app = FastAPI()

# Configuration values provided
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-qia71wrf.apps.exam.local"

# Request schema
class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
async def verify_token(payload: TokenRequest):
    try:
        # PyJWT handles signature verification, expiration (exp), 
        # audience (aud), and issuer (iss) validations all at once.
        decoded_payload = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER
        )
        
        # Safely extract claims to return
        return {
            "valid": True,
            "email": decoded_payload.get("email"),
            "sub": decoded_payload.get("sub"),
            "aud": decoded_payload.get("aud")
        }

    except (InvalidTokenError, ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError):
        # Catch any structural, signature, or claim mismatch errors
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"valid": False}
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
