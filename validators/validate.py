from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from typing import Optional, List
from urllib.parse import urlparse
from datetime import date, time, datetime
from decimal import Decimal
from enum import Enum
import re


class ItemCategoryEnum(str, Enum):
    FOOD = "FOOD"
    MEDICINE = "MEDICINE"
    EQUIPMENT = "EQUIPMENT"


class PaymentMethodEnum(str, Enum):
    CASH = "CASH"
    UPI = "UPI"
    BANK_TRANSFER = "BANK_TRANSFER"


class UserProfileReferenceModel(BaseModel):
    user_id: int = Field(..., gt=0, description="Unique user ID")
    full_name: str = Field(..., min_length=3, max_length=100)
    email: EmailStr
    phone_number: str = Field(..., description="10 digit Indian mobile number")
    profile_url: Optional[str] = Field(None, max_length=500)

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str):
        if not re.fullmatch(r"^[6-9]\d{9}$", v):
            raise ValueError("Invalid Indian mobile number")
        return v

    @field_validator("profile_url")
    @classmethod
    def validate_url(cls, v: Optional[str]):
        if v is None:
            return v
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "user_id": 101,
                "full_name": "Kalyan Ontipuli",
                "email": "kalyan@example.com",
                "phone_number": "9398662859",
                "profile_url": "https://example.com/photo.jpg",
            }
        }
    }


class FinancialTransactionReferenceModel(BaseModel):
    transaction_id: str = Field(..., min_length=5, max_length=50)
    amount: Decimal = Field(..., gt=0, max_digits=10, decimal_places=2)
    transaction_time: datetime
    payment_method: PaymentMethodEnum
    reference_number: Optional[str] = None

    @model_validator(mode="after")
    def validate_reference_required(self):
        if (
            self.payment_method == PaymentMethodEnum.BANK_TRANSFER
            and not self.reference_number
        ):
            raise ValueError("reference_number is required for BANK_TRANSFER")
        return self

    model_config = {
        "json_schema_extra": {
            "example": {
                "transaction_id": "TXN1001",
                "amount": 12500.50,
                "transaction_time": "2026-02-23T10:30:00",
                "payment_method": "BANK_TRANSFER",
                "reference_number": "HDFC12345XYZ",
            }
        }
    }


class ScheduleBookingReferenceModel(BaseModel):
    booking_id: int = Field(..., gt=0)
    booking_date: date
    start_time: time
    end_time: time
    participants: List[str] = Field(..., min_length=1)

    @field_validator("booking_date")
    @classmethod
    def validate_date(cls, v: date):
        if v < date.today():
            raise ValueError("booking_date cannot be in the past")
        return v

    @model_validator(mode="after")
    def validate_time_range(self):
        if self.end_time <= self.start_time:
            raise ValueError("end_time must be after start_time")
        return self

    model_config = {
        "json_schema_extra": {
            "example": {
                "booking_id": 1,
                "booking_date": "2026-03-10",
                "start_time": "09:00",
                "end_time": "11:00",
                "participants": ["user1", "user2"],
            }
        }
    }


class InventoryItemReferenceModel(BaseModel):
    item_code: str = Field(..., description="Format: ITEM-XXXX")
    name: str = Field(..., min_length=2, max_length=100)
    price: float = Field(..., gt=0)
    in_stock: bool
    category: ItemCategoryEnum

    @field_validator("item_code")
    @classmethod
    def validate_item_code(cls, v: str):
        if not re.fullmatch(r"^ITEM-\d{4}$", v):
            raise ValueError("item_code must follow format ITEM-1234")
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "item_code": "ITEM-1001",
                "name": "Cattle Feed",
                "price": 1450.75,
                "in_stock": True,
                "category": "FOOD",
            }
        }
    }
