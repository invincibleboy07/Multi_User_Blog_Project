from google.appengine.ext import db


# database for users
class Users(db.Model):
    user_name = db.StringProperty(required=True)
    user_password = db.StringProperty(required=True)
    user_email = db.StringProperty()


# Database for Likes
class Likes(db.Model):
    post_id = db.StringProperty(required=True)
    username = db.StringProperty(required=True)


# Database for comments
class Comments(db.Model):
    username = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    post_id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
