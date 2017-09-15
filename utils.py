from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_config import Base, Category, Item, User
from flask import session

class Utils():
	@staticmethod
	def connect():
		engine = create_engine('sqlite:///SportsCatalog.db')
		Base.metadata.bind = engine

		DBSession = sessionmaker(bind=engine)
		session = DBSession()
		return session

