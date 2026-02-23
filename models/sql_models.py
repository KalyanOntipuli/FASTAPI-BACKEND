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
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy import Enum as SQLEnum
from models import Base


# ---------------- ENUMS ---------------- #

class RoleEnum(str, Enum):
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

    camera_config = Column(JSONB)

    # ---------------- OTP FIELDS ---------------- #

    signup_otp_count = Column(Integer, default=0, nullable=False)
    signup_latest_otp_requested_date = Column(DateTime(timezone=True))

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
