import uuid
import pytz
from datetime import datetime, timedelta
from enum import Enum

from sqlalchemy import (
    Column,
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
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


# ---------------- ENUMS ---------------- #


class RoleEnum(
    str, Enum
):  # We inherit from str so each enum member behaves like a normal string (e.g., can be compared to and serialized as a string).
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


class User(Base):
    """
    User model with fields for personal information, roles, contact details, andResponsibilities of Base:
    - Registers the model with SQLAlchemy’s ORM system.
    - Tracks table metadata (columns, constraints, relationships).
    - Maps the Python class to a corresponding database table.
    - Provides a default constructor that assigns keyword arguments to columns.
    - Manages ORM internals such as state tracking, session integration,
    change detection, and persistence behavior.

    All database models must inherit from Base to participate in
    SQLAlchemy’s ORM functionality.
    """
    """
    The User model represents a user in the system with various attributes such as
    """
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)

    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)

    roles = Column(
        ARRAY(SQLEnum(RoleEnum, name="user_role_enum")),
        nullable=False,
    )

    employment_status = Column(
        SQLEnum(EmploymentStatusEnum, name="employment_status_enum"),
        default=EmploymentStatusEnum.ON_DUTY,
    )

    email = Column(String(100), unique=True)
    mobile = Column(String(15), unique=True, nullable=False)

    address = Column(String(255))
    city = Column(String(50))
    state = Column(String(50))
    pincode = Column(String(10))

    is_active = Column(Boolean, default=True)
    is_test = Column(Boolean, default=False)

    profile_image_url = Column(String(255))
    images = Column(ARRAY(String))

    camera_config = Column(JSONB, nullable=True)
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
        JSONB -> Binary (decomposed storage)

    Speed:
        JSON  -> Slower (re-parsed on each read)
        JSONB -> Faster (stored in parsed binary format)

    Index Support:
        JSON  -> Limited
        JSONB -> Full indexing support (GIN / B-Tree)

    Duplicate Keys:
        JSON  -> Allowed
        JSONB -> Not allowed (last key overwrites previous)

    Query Performance:
        JSON  -> Slower
        JSONB -> Optimized for searching and filtering

    Why JSONB is Used Here
    ----------------------
    This field stores dynamic camera configuration data such as:
        - Resolution
        - Frame rate
        - Night mode settings
        - Detection zones
        - Custom metadata

    The structure may vary per record, so a flexible schema is preferred.

    When to Use JSONB
    -----------------
    Use JSONB when:
        - Data structure varies between records
        - You need flexible or optional fields
        - Storing configuration or metadata
        - Fast querying inside JSON fields is required
        - Indexing JSON keys is needed

    When NOT to Use JSONB
    ---------------------
    Avoid JSONB when:
        - Data has a strict relational structure
        - Frequent updates on individual fields are required
        - Strong foreign key constraints are needed
        - Large-scale analytical queries depend on structured columns
        - Data should be normalized into separate tables

    Note:
    -----
    For core relational data (like user name, email, foreign keys),
    normal columns are preferred. JSONB is best for semi-structured
    or dynamic data.
    """

    # ---------------- OTP FIELDS ---------------- #

    signup_otp_count = Column(Integer, default=0, nullable=False)
    signup_latest_otp_requested_date = Column(DateTime(timezone=True))
    """
    All timestamps are stored in UTC to ensure consistency across different
    time zones and regions. Using a single standard time (UTC) prevents
    errors in comparisons, expiration logic, and distributed systems.
    """

    forgot_password_otp_count = Column(Integer, default=0, nullable=False)
    forgot_password_latest_otp_requested_date = Column(DateTime(timezone=True))

    account_reactivation_otp_count = Column(Integer, default=0, nullable=False)
    account_reactivation_latest_otp_requested_date = Column(DateTime(timezone=True))

    # ---------------- TIME FIELDS ---------------- #

    time = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(pytz.timezone("Asia/Kolkata")),
    )

    last_login = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

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

    """__repr__() defines how your object looks when printed or logged, mainly for 
                debugging and developer clarity."""


class Order(Base):
    __tablename__ = "orders"

    id = Column(String, primary_key=True, default=generate_uuid)

    user_id = Column(String, ForeignKey("users.id"), nullable=False)

    order_no = Column(String, unique=True, nullable=False)

    reason = Column(Text, nullable=False)

    start_time = Column(Time, nullable=False)
    end_time = Column(Time, nullable=False)

    request_date = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(pytz.timezone("Asia/Kolkata")),
    )

    request_expired_date = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), server_default=func.now())

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


class Certification(Base):
    __tablename__ = "certifications"

    id = Column(String, primary_key=True)

    user_id = Column(String, ForeignKey("users.id"), nullable=False)

    request_date = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(pytz.timezone("Asia/Kolkata")),
    )

    request_expired_date = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.id = self.generate_unique_id()

        self.request_date = datetime.now(pytz.timezone("Asia/Kolkata"))
        self.request_expired_date = self.request_date + timedelta(days=10)

    def generate_unique_id(self):
        return "MAANG-" + str(uuid.uuid4())[:15]

    def __repr__(self):
        return f"<Certification(id={self.id}, user_id={self.user_id})>"

