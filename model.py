from sqlalchemy import Column, Integer, String, Float, DateTime
from database import Base
from datetime import datetime

class PredictionLog(Base):
    __tablename__ = "prediction_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500))
    prediction = Column(String(50))
    confidence = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
