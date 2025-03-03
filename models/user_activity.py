from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    Boolean,
    DateTime,
    func,
    ForeignKey,
)
from infra.database import Base


class UserActivity(Base):
    __tablename__ = "useractivity"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("user.id"))
    login_success_count = Column(Integer, default=0)
    login_failed_count = Column(Integer, default=0)
    last_successful_login = Column(String)
    last_failed_login = Column(String)
    is_active = Column(Boolean, default=True)
    created_by = Column(String)
    modified_by = Column(String)
    created_date = Column(DateTime(timezone=False), server_default=func.now())
    modified_date = Column(DateTime(timezone=False), onupdate=func.now())
