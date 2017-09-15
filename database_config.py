from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
	__tablename__= 'users'

	id = Column(Integer, primary_key= True)
	name = Column(String(250), nullable= False)
	email = Column(String(250), nullable= False)
	picture= Column(String(250))


class Category(Base):
	__tablename__ = 'categories'

	id = Column(Integer, primary_key= True)
	name= Column(String(250), nullable= False)
	image = Column(String(250))
	user_id = Column(Integer, ForeignKey('users.id'))
	items = relationship('Item', backref="category", cascade="all, delete-orphan", lazy='dynamic') 
	user = relationship(User)

	@property
	def serialize(self):
		return {
			'name': self.name,
			'id': self.id,
		}


class Item(Base):
	__tablename__='items'


	name =Column(String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	description = Column(String(250))
	category_id = Column(Integer,ForeignKey('categories.id'))
	user_id = Column(Integer, ForeignKey('users.id'))
	user = relationship(User)

	@property
	def serialize(self):
		return {
    		'name': self.name,
    		'id': self.id,
    		'description': self.description,
    	}


engine = create_engine('postgresql://sportsCatalog:password@localhost/SportsCatalog')


Base.metadata.create_all(engine)