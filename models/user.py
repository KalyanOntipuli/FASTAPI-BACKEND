from infra.database import Base
from sqlalchemy import Column, Integer, String, Boolean


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    phone_number = Column(String, unique=True)
    first_name = Column(String)
    last_name = Column(String)
    password = Column(String)
    role = Column(String, default="normal_user")
    is_active = Column(Boolean, default=True)
