# Standard library imports
from datetime import datetime, timedelta
from typing import Annotated, Optional

# Third-party imports
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session
from jose import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Local application/library imports
from infra.database import SessionLocal
from models.user import User
from models.user_activity import UserActivity
from utilities.constants import JWT_SECRET_KEY, JWT_ENCODING_ALGORITHM

# Router setup: Initializes a FastAPI router for authentication-related routes
router = APIRouter(prefix="/auto", tags=["Auth"])

# Password hashing context: Uses bcrypt for password hashing and verification
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 bearer token setup: Defines the token URL and specifies the OAuth2Bearer for authentication
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")


# Dependency for database session: Defines a function to handle database session lifecycle
def get_db():
    db = SessionLocal()  # Open a new session
    try:
        yield db  # Provide the session for use in the function
    finally:
        db.close()  # Close the session once done


# Create an alias for db dependency injection: Annotates the db dependency to be used in FastAPI route functions
db_dependency = Annotated[Session, Depends(get_db)]


# Token model: Defines the response model for the access token
class Token(BaseModel):
    access_token: str
    token_type: str


# Utility functions for password hashing and verification


def get_password_hash(password: str) -> str:
    # Hashes the password using bcrypt
    return bcrypt_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Verifies if the given password matches the hashed password
    return bcrypt_context.verify(plain_password, hashed_password)


# Authentication logic: Checks if the user exists and the password is correct
def authenticate_user(
    input_value: str, password: str, db: db_dependency
) -> Optional[User]:
    user = (
        db.query(User)
        .filter(
            User.is_active == True,
            (User.email == input_value) | (User.phone_number == input_value),
        )
        .first()
    )
    if user and bcrypt_context.verify(password, user.hashed_password):
        return user
    return None


# JWT token creation: Generates a JWT token for the authenticated user
def create_access_token(
    user_id: int, user_email: str, role: str, expires_delta: Optional[timedelta] = None
) -> str:
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta
        else timedelta(minutes=15)  # Default expiration time is 15 minutes
    )
    to_encode = {
        "user_id": user_id,
        "user_email": user_email,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(to_encode, JWT_SECRET_KEY, JWT_ENCODING_ALGORITHM)


# Dependency for extracting the current user from JWT token: Decodes the JWT token to get user info
def get_current_user(token: str, db: db_dependency) -> dict:
    try:
        payload = jwt.decode(
            token, JWT_SECRET_KEY, algorithms=[JWT_ENCODING_ALGORITHM]
        )  # Decode JWT token
        user_id = payload.get("user_id")
        user_email = payload.get("user_email")

        if not user_email:
            raise get_user_exception()  # Raise exception if the token doesn't contain a valid email

        user = (
            db.query(User).filter(User.is_active == True, User.id == user_id).first()
        )  # Query the user from the database
        if not user:
            raise get_user_exception()  # Raise exception if user does not exist

        return {"username": user.username, "user_id": user.id, "email": user.email}

    except jwt.JWTError as e:
        raise get_user_exception() from e  # Raise exception if JWT error occurs


# Route to generate a token upon successful login
@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency
):
    try:
        # Query user by username
        input_value = form_data.username.strip()
        db_user = (
            db.query(User)
            .filter(
                User.is_active == True,
                (User.email == input_value) | (User.phone_number == input_value),
            )
            .first()
        )

        # If user is not found, return an error response
        if not db_user:
            return JSONResponse(
                {"detail": "INVALID PHONE_NUMBER OR EMAIL"}, status_code=401
            )  # Return error if user not found

        # Authenticate the user by checking the credentials (using hashed password check)
        user = authenticate_user(input_value, form_data.password.strip(), db)

        # Check if user activity exists (e.g., login history)
        if db_user:
            db_user_activity = (
                db.query(UserActivity)
                .filter(
                    UserActivity.is_active == True, UserActivity.user_id == db_user.id
                )
                .first()
            )

        # If authentication fails, log the failed attempt and return an error message
        if not user:
            if db_user and db_user_activity:
                db_user_activity.login_failed_count += 1  # Increment failed login count
                db_user_activity.last_failed_login = str(
                    datetime.now()
                )  # Log failed attempt time
                db.commit()
            return JSONResponse({"detail": "INCORRECT PASSWORD"}, status_code=401)

        # Token expires in 40 minutes
        token_expires = timedelta(40)
        token = create_access_token(
            user.username, user.id, user.email, expires_delta=token_expires
        )  # Create access token

        # If token creation is successful, update user activity and return token
        if token:
            if db_user_activity:
                db_user_activity.login_success_count += (
                    1  # Increment successful login count
                )
                db_user_activity.last_successful_login = str(
                    datetime.now()
                )  # Log successful login time
                db.add(db_user_activity)  # Add updated user activity
                db.commit()
            return {
                "access_token": token,
                "token_type": "Bearer",
            }  # Return the token and token type

    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="token not generated",  # Raise an internal server error if token generation fails
        )

    finally:
        if db:
            db.close()  # Ensure that the database session is closed after processing the request


# Custom exception for invalid credentials: Creates a custom error response for invalid credentials
def get_user_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",  # Error message for invalid credentials
        headers={
            "WWW-Authenticate": "Bearer"
        },  # Adds 'WWW-Authenticate' header for token-based authentication
    )
