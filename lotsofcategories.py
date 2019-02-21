from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from model import Base, User, Category, Item

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# To delete all entries:
# session.query(Category).delete()
# session.query(Item).delete()
# session.query(Item).filter_by(name='Jacket').delete()

# session.commit()

# Categories
soccer = Category(user_id=1, name="Soccer")
session.add(soccer)
session.commit()

basketball = Category(user_id=1, name="Basketball")
session.add(basketball)
session.commit()

baseball = Category(user_id=1, name="Baseball")
session.add(baseball)
session.commit()

tennis = Category(user_id=1, name="Tennis")
session.add(tennis)
session.commit()

snowboarding = Category(user_id=1, name="Snowboarding")
session.add(snowboarding)
session.commit()

skating = Category(user_id=1, name="Skating")
session.add(skating)
session.commit()

# Items

user = User(username='Tester', picture='picture', email='test@gmail.com')
session.add(user)
session.commit()

skate = session.query(Category).filter_by(name='Skating').one()
bb = Item(user_id=user.id, name="Dress",
          description="Ice skating dress one performs in",
          category=skate)

session.add(bb)
session.commit()

bb = Item(user_id=1, name="Basketball Hoop",
          description="Metal hoop with a net to shoot the basketball into.",
          category=basketball)
session.add(bb)
session.commit()

soccerBall = Item(user_id=1, name="Soccer cleats",
                  description="Shoes worn whie play Soccer. " +
                  "They have spikes on the bottom.", category=soccer)
session.add(soccerBall)
session.commit()

baseb = Item(user_id=1, name="Baseball bat",
             description="A wooden or metal bat used to hit a ball.",
             category=baseball)
session.add(baseb)
session.commit()

tennisBall = Item(user_id=1, name="Ball",
                  description="A ball made out of synthetic leather" +
                  " used in the game of Soccer", category=tennis)
session.add(tennisBall)
session.commit()

racket = Item(user_id=1, name="Racket", description="A hand held " +
	          "racket used to hit a tennis ball across the court.",
              category=tennis)
session.add(racket)
session.commit()

snowboard = Item(user_id=1, name="Snowboard"
                 description="A winterized skateboard with no wheels.",
                 category=snowboarding)
session.add(snowboard)
session.commit()

googles = Item(user_id=1, name="Goggles",
               description="Eye protection while snowboarding.",
               category=snowboarding)
session.add(googles)
session.commit()

skates = Item(user_id=1, name="Skates", description="Shoes with " +
              "blades on the bottom so one can glide across ice.",
              category=skating)
session.add(skates)
session.commit()
