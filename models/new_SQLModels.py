import uuid
import pytz
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Dict

from sqlmodel import SQLModel, Field, Column
from sqlalchemy import (
    String,
    Integer,
    DateTime,
    Boolean,
    Text,
    Time,
    ForeignKey,
    func,
    ARRAY,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Enum as SQLEnum


# ---------------- ENUMS ---------------- #

class RoleEnum(str, Enum):
    """
    We inherit from str so each enum member behaves like a normal string
    (e.g., can be compared to and serialized as a string).
    """
    INVESTOR = "INVESTOR"
    FARM_MANAGER = "FARM_MANAGER"
    SUPERVISOR = "SUPERVISOR"
    DOCTOR = "DOCTOR"
    ASSISTANT_DOCTOR = "ASSISTANT_DOCTOR"
    ADMIN = "ADMIN"


class EmploymentStatusEnum(str, Enum):
    ON_DUTY = "ON_DUTY"
    ON_LEAVE = "ON_LEAVE"
    SUSPENDED = "SUSPENDED"
    TERMINATED = "TERMINATED"
    RESIGNED = "RESIGNED"
    ABSCONDED = "ABSCONDED"
    INACTIVE = "INACTIVE"


def generate_uuid():
    return str(uuid.uuid4())


# ---------------- USERS TABLE ---------------- #

class User(SQLModel, table=True):
    """
    User model with fields for personal information, roles, contact details.

    SQLModel Responsibilities:
    - Combines SQLAlchemy ORM + Pydantic validation.
    - Automatically maps this class to a database table.
    - Provides request validation for FastAPI.
    - Tracks table metadata (columns, constraints, relationships).
    - Handles persistence behavior and ORM state management.
    """

    __tablename__ = "users"

    id: str = Field(default_factory=generate_uuid, primary_key=True)

    first_name: str = Field(sa_column=Column(String(50), nullable=False))
    last_name: str = Field(sa_column=Column(String(50), nullable=False))

    roles: List[RoleEnum] = Field(
        sa_column=Column(
            ARRAY(SQLEnum(RoleEnum, name="user_role_enum")),
            nullable=False,
        )
    )

    employment_status: EmploymentStatusEnum = Field(
        default=EmploymentStatusEnum.ON_DUTY,
        sa_column=Column(SQLEnum(EmploymentStatusEnum, name="employment_status_enum")),
    )

    email: Optional[str] = Field(default=None, sa_column=Column(String(100), unique=True))
    mobile: str = Field(sa_column=Column(String(15), unique=True, nullable=False))

    address: Optional[str] = Field(default=None, sa_column=Column(String(255)))
    city: Optional[str] = Field(default=None, sa_column=Column(String(50)))
    state: Optional[str] = Field(default=None, sa_column=Column(String(50)))
    pincode: Optional[str] = Field(default=None, sa_column=Column(String(10)))

    is_active: bool = Field(default=True, sa_column=Column(Boolean))
    is_test: bool = Field(default=False, sa_column=Column(Boolean))

    profile_image_url: Optional[str] = Field(default=None, sa_column=Column(String(255)))

    images: Optional[List[str]] = Field(
        default=None,
        sa_column=Column(ARRAY(String)),
    )

    camera_config: Optional[Dict] = Field(
        default=None,
        sa_column=Column(JSONB),
    )

    """
    JSONB (JSON Binary) column for storing semi-structured configuration data.

    What is JSONB?
    --------------
    JSONB is a PostgreSQL data type that stores JSON data in a decomposed binary
    format instead of plain text. It allows efficient querying, indexing,
    and partial updates.

    JSON vs JSONB Comparison
    ------------------------
    Storage Type:
        JSON  -> Text
        JSONB -> Binary

    Speed:
        JSON  -> Slower
        JSONB -> Faster

    Index Support:
        JSON  -> Limited
        JSONB -> Full indexing support

    Duplicate Keys:
        JSON  -> Allowed
        JSONB -> Not allowed
    """

    # ---------------- OTP FIELDS ---------------- #

    signup_otp_count: int = Field(default=0, sa_column=Column(Integer, nullable=False))
    signup_latest_otp_requested_date: Optional[datetime] = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )

    forgot_password_otp_count: int = Field(default=0, sa_column=Column(Integer, nullable=False))
    forgot_password_latest_otp_requested_date: Optional[datetime] = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )

    account_reactivation_otp_count: int = Field(default=0, sa_column=Column(Integer, nullable=False))
    account_reactivation_latest_otp_requested_date: Optional[datetime] = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )

    # ---------------- TIME FIELDS ---------------- #

    time: datetime = Field(
        default_factory=lambda: datetime.now(pytz.timezone("Asia/Kolkata")),
        sa_column=Column(DateTime(timezone=True)),
    )

    last_login: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True)),
    )

    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), server_default=func.now())
    )

    updated_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), onupdate=func.now()),
    )

    """
    All timestamps are stored in UTC to ensure consistency across different
    time zones and regions.
    """

    # ---------------- OTP LIMIT METHODS ---------------- #

    def _is_limit_exceeded(self, count, last_request, limit=3, cooldown_hours=6):
        if count >= limit and last_request:
            reset_time = last_request + timedelta(hours=cooldown_hours)
            return datetime.now(pytz.UTC) < reset_time
        return False

    def is_signup_limit_exceeded(self):
        return self._is_limit_exceeded(
            self.signup_otp_count,
            self.signup_latest_otp_requested_date,
        )

    def is_forgot_password_limit_exceeded(self):
        return self._is_limit_exceeded(
            self.forgot_password_otp_count,
            self.forgot_password_latest_otp_requested_date,
        )

    def is_account_activation_limit_exceeded(self):
        return self._is_limit_exceeded(
            self.account_reactivation_otp_count,
            self.account_reactivation_latest_otp_requested_date,
        )

    def __repr__(self):
        return f"<User(id={self.id}, mobile={self.mobile}, roles={self.roles})>"


# ---------------- ORDERS TABLE ---------------- #

class Order(SQLModel, table=True):

    __tablename__ = "orders"

    id: str = Field(default_factory=generate_uuid, primary_key=True)

    user_id: str = Field(
        sa_column=Column(String, ForeignKey("users.id"), nullable=False)
    )

    order_no: str = Field(sa_column=Column(String, unique=True, nullable=False))

    reason: str = Field(sa_column=Column(Text, nullable=False))

    start_time: datetime = Field(sa_column=Column(Time, nullable=False))
    end_time: datetime = Field(sa_column=Column(Time, nullable=False))

    request_date: datetime = Field(
        default_factory=lambda: datetime.now(pytz.timezone("Asia/Kolkata")),
        sa_column=Column(DateTime(timezone=True)),
    )

    request_expired_date: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True)),
    )

    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), server_default=func.now())
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.order_no = self.generate_unique_id()

        if not self.request_date:
            self.request_date = datetime.now(pytz.timezone("Asia/Kolkata"))

        self.request_expired_date = self.request_date + timedelta(days=10)

    def generate_unique_id(self):
        return "MAANG-" + str(uuid.uuid4())[:8]

    def __repr__(self):
        return f"<Order(order_no={self.order_no}, user_id={self.user_id})>"


# ---------------- CERTIFICATIONS TABLE ---------------- #

class Certification(SQLModel, table=True):

    __tablename__ = "certifications"

    id: str = Field(primary_key=True)

    user_id: str = Field(
        sa_column=Column(String, ForeignKey("users.id"), nullable=False)
    )

    request_date: datetime = Field(
        default_factory=lambda: datetime.now(pytz.timezone("Asia/Kolkata")),
        sa_column=Column(DateTime(timezone=True)),
    )

    request_expired_date: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True)),
    )

    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), server_default=func.now())
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.id = self.generate_unique_id()

        self.request_date = datetime.now(pytz.timezone("Asia/Kolkata"))
        self.request_expired_date = self.request_date + timedelta(days=10)

    def generate_unique_id(self):
        return "MAANG-" + str(uuid.uuid4())[:15]

    def __repr__(self):
        return f"<Certification(id={self.id}, user_id={self.user_id})>"
