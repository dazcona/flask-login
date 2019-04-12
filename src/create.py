from app import db, User

# create the database and the db table
db.create_all()

# insert data
db.session.add(User("david", "david.azcona2@mail.dcu.ie", "david1!", "David", "Azcona"))

# commit the changes
db.session.commit()

print('BD created and populated with Admin')