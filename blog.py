import os
import re
from string import letters
import webapp2
import jinja2
import random
import string
import re
import hashlib
from google.appengine.ext import ndb
from google.appengine.ext import db
from modals import Users, Likes, Comments

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# renders template with passed values
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# database for blog posts
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    username = db.StringProperty(required=True)

    def render(self):
        # replacing all line breaks to <br> html tag
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# specifies all common functions
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['global_username'] = self.global_username
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # encryption functions
    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in range(5))

    def make_pw_hash(self, name, password, salt=None):
        if salt is None:
            salt = self.make_salt()
        hasher = hashlib.sha256("%s%s%s" % (name, password, salt)).hexdigest()
        return "%s|%s" % (hasher, salt)

    def valid_pw(self, name, password, hashed_value):
        salt = hashed_value.split('|')[1]
        return hashed_value == self.make_pw_hash(name, password, salt)

    def make_hash_cookie(self, user_id):
        secret = "SECRETT"
        hashed = hashlib.sha256("%s%s" % (user_id, secret)).hexdigest()
        return "%s|%s" % (user_id, hashed)

    def check_hash_cookie(self, cookie):
        user_id = cookie.split("|")[0]
        return cookie == self.make_hash_cookie(user_id)

    # get current user
    def get_current_user(self):
        usr = self.request.cookies.get('user_id', 0)
        if usr and self.check_hash_cookie(usr):
            list = usr.split("|")
            return list[0]
        else:
            return None

    # returns comment when comment's id given
    def get_comment(self, comment_id):
        key = db.Key.from_path('Comments', int(comment_id),
                               parent=blog_key())
        return db.get(key)

    # to check in user in looged in
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.global_username = self.get_current_user()


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post   order by created desc")
        # due to eventual consistency deltete virtually and data deleted later
        post_deleted = self.request.get('post_deleted')
        self.render('front.html', posts=posts, post_deleted=post_deleted)


# for format checking of login and sign up details

def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)


# signup
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        if password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        # check if username adlready exists
        query_string = """select * from Users
                        where user_name='%s'"""
        user = db.GqlQuery(query_string % username)
        ind_user = user.get()
        if bool(ind_user) and (ind_user.user_name == username):
            params['error_username'] = "already exists"
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            hashed_cookie = self.make_hash_cookie(username)
            self.response.headers.add_header(
                'Set-Cookie',
                'user_id = %s;Path=/' % str(hashed_cookie))
            hashed_password = self.make_pw_hash(username, password)
            user_instance = Users(user_name=username,
                                  user_password=hashed_password,
                                  user_email=email)
            user_instance.put()
            self.redirect('/welcome')


class WelcomeHandler(BlogHandler):
    def get(self):

        usr = self.request.cookies.get('user_id', 0)
        if usr and self.check_hash_cookie(usr):
            list = usr.split("|")
            self.render("welcome.html",
                        username=list[0],
                        p=1)
        else:
            self.redirect('/signup')


# login
class LoginHandler(BlogHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        usr_name = self.request.get("username")
        usr_pass = self.request.get("password")

        username_error = ""
        password_error = ""
        login_error = ""
        have_error = False
        if not valid_username(usr_name):
            username_error = "That's not a valid username format"
            have_error = True

        if not valid_password(usr_pass):
            password_error = "That wasn't a valid password format"
            have_error = True

        # check Password if both are valid format
        if have_error is False:
            pass_error = False
            usr = db.GqlQuery(
                "select * from Users where user_name='%s'" % usr_name)
            if usr:
                row = usr.get()
                if row and self.valid_pw(usr_name,
                                         usr_pass,
                                         row.user_password):
                    pass_error = False
                else:
                    pass_error = True
                    login_error = ("invalid login. Username"
                                   "or password is invalid!!")

        if have_error or pass_error:
            self.render("login.html",
                        username_error=username_error,
                        password_error=password_error,
                        login_error=login_error)
        else:
            hashed_cookie = self.make_hash_cookie(usr_name)
            self.response.headers.add_header('Set-Cookie',
                                             'user_id=%s' % str(hashed_cookie),
                                             path='/')
            self.redirect("/welcome")


# new post adder
class NewPost(BlogHandler):
    def get(self):
        user = self.get_current_user()
        if user:
            self.render("newpost.html")
        else:
            self.redirect('/login')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        # take the name from coookie
        user = self.get_current_user()
        if subject and content:
                p = Post(subject=subject, content=content, username=user)
                p.put()
                self.redirect('/%s' % str(p.key().id()))
        else:
                error = "subject and content, please!"
                self.render("newpost.html", subject=subject,
                            content=content,
                            error=error)


# parent key
def blog_key(name='default'):
    return db.Key.from_path('/', name)


# post shown after new post added
class PostPage(BlogHandler):

    def get_likes(self, post_id, username=None):
        if username:
            query_string = """select * from Likes
                              where post_id='%s' and username='%s'
                              and ANCESTOR IS :1"""
            likes = db.GqlQuery(query_string % (post_id, username), blog_key())
            no_likes = likes.count()
        else:
            query_string = """select * from Likes
                              where post_id='%s' and ANCESTOR IS :1"""
            likes = db.GqlQuery(query_string % (post_id), blog_key())
            no_likes = likes.count()
        return no_likes

    # increase like
    def increment_likes(self, post_id, username):
        like = Likes(parent=blog_key(),
                     post_id=post_id,
                     username=username)
        like.put()

    # delete the like of that user
    def delete_likes(self, post_id, username):
        query_string = """select * from Likes
                          where post_id='%s' and username='%s'
                          and ANCESTOR IS :1"""
        likes = db.GqlQuery(query_string % (post_id, username), blog_key())
        q = likes[0]
        q.delete()

    # get user that posted the blog
    def get_post_user(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        return post.username

    def check_if_liked(self, post_id):
        user = self.get_current_user()
        if user:
            like = self.get_likes(post_id, user)
            if like:
                isliked = True
            else:
                isliked = False

        else:
            isliked = False
        return isliked

    def get_comments(self, post_id):
        query_string = """select * from Comments
                          where post_id='%s'
                          and ANCESTOR IS :1"""
        return db.GqlQuery(query_string % (post_id), blog_key())

    def add_comment(self, comment, post_id):
        username = self.get_current_user()
        q = Comments(parent=blog_key(),
                     username=username,
                     content=comment,
                     post_id=post_id)
        q.put()

    # get here
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        # dictionary for additional information
        dic = {}
        # get num of likes
        num_likes = self.get_likes(post_id)
        dic['num_likes'] = num_likes
        # see if user has liked or not
        dic['isliked'] = self.check_if_liked(post_id)
        error = self.request.get('error')
        # replace line break
        post.content = post.content.replace('\n', '<br>')
        # get comments
        comments = self.get_comments(post_id)
        # self._render_text = self.content.replace('\n', '<br>')
        self.render("permalink.html",
                    post=post,
                    dic=dic,
                    comments=comments,
                    error=error)

    def post(self, post_id):
        user = self.get_current_user()
        # handele unsigned user here
        edit_clicked = self.request.get('edit-clicked')
        self.request.get('subject')
        self.request.get('subject')

        # check is user is signed or not
        if user:
            clicked_request = self.request.get('comment-clicked')
            is_comment_clicked = (clicked_request == "clicked")
            # check is user clicked comment or like
            if is_comment_clicked:
                comment = self.request.get('comment')
                #checkif comment is empty
                if comment:
                    self.add_comment(comment, post_id)
                    self.redirect('/%s' % (post_id))
                else:
                    error = "Content for comment needed"
                    self.redirect('/%s?error=%s' % (post_id, error))

            else:
                post_user = self.get_post_user(post_id)
                # check if user is trying to like his own post
                if user == post_user:
                            error = "cannot like your own post"
                            self.redirect('/%s?error=%s' % (post_id, error))
                else:
                            isliked = self.request.get('liked')
                            if isliked == "True":
                                # unlike button
                                self.delete_likes(post_id, user)
                            else:
                                # like button
                                self.increment_likes(post_id, user)
                            self.redirect('/%s' % (post_id))

        else:
            # if not signed in
            self.redirect('/login')


# editing post
class EditPost(BlogHandler):

    # returns post by post_id
    def get_post(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        if not post:
            self.error(404)
            return
        return post

    def get(self, post_id):
        user = self.get_current_user()
        post = self.get_post(post_id)
        # check if user is signed in
        if user:
            # check is user is eligible for editing
            if post.username == user:
                subject = post.subject
                content = post.content
                self.render('editpost.html',
                            subject=subject,
                            content=content)
            else:
                error = "You donot have permission to edit this post"
                self.redirect('/%s?error=%s' % (post_id, error))
        else:
            self.redirect('/login')

    def post(self, post_id):
        subject = self.request.get('title')
        content = self.request.get('content')
        # check if user entered both
        if subject and content:
            post = self.get_post(post_id)
            post.subjec = subject
            post.content = content
            post.put()
            self.redirect('/%s' % post_id)
        else:
            error = "subject and content needed"
            self.render('editpost.html',
                        subject=subject,
                        content=content,
                        error=error)


class DeletePost(BlogHandler):

    def get(self, post_id):
        user = self.get_current_user()
        # check if user is signed in
        if user:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            # check if post exists
            if not post:
                self.error(404)
                return
            # check if user is eligible to delete
            if post.username == user:
                db.delete(post)
                self.redirect('/?post_deleted=' + post_id)
            else:
                error = "Sorry!!You cannot delete others post"
                self.redirect('/%s?error=%s' % (post_id, error))
        else:
            self.redirect('/login')


# edit comment
class EditComment(BlogHandler):
    def get(self, comment_id):
        user = self.get_current_user()
        comment = self.get_comment(comment_id)
        if not comment:
            self.error(404)
            return
        # check is user is signed in
        if user:
            # check if user eligible to edit
            if comment.username == user:
                self.render('editcomment.html', content=comment.content)
            else:
                error = "you cannot edit others comment"
                self.redirect('/%s?error=%s' % (comment.post_id, error))
        else:
            self.redirect('/login')

    def post(self, comment_id):
        content = self.request.get('content')
        comment = self.get_comment(comment_id)
        if content:
            comment.content = content
            comment.put()
            self.redirect('/%s' % (comment.post_id))
        else:
            error = "content needed"
            self.redirect('/%s?error=%s' % (comment.post_id, error))


# Delete comment
class DeleteComment(BlogHandler):
    def get(self, comment_id):
        comment = self.get_comment(comment_id)
        # checkif comment exists
        if not comment:
            self.error(404)
            return
        # check if loged in
        user = self.get_current_user()
        if user:
            # check if user is eligible
            if user == comment.username:
                post_id = comment.post_id
                db.delete(comment)
                self.redirect('/%s?error=%s' % (post_id, "DELETED"))
            else:
                error = "you cannot delete others comment"
                self.redirect('/%s?error=%s' % (comment.post_id, error))
        else:
            self.redirect('/login')


# logout
class LogoutHandler(BlogHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=%s' % "",
                                         path='/')
        self.redirect('/signup')


# credits
class CreditsHandler(BlogHandler):
    def get(self):
        self.render('/credits.html')

app = webapp2.WSGIApplication([
                               ('/', BlogFront),
                               ('/signup', Signup),
                               ('/welcome', WelcomeHandler),
                               ('/login', LoginHandler),
                               ('/newpost', NewPost),
                               ('/([0-9]+)', PostPage),
                               ('/editpost/([0-9]+)', EditPost),
                               ('/deletepost/([0-9]+)', DeletePost),
                               ('/editcomment/([0-9]+)', EditComment),
                               ('/deletecomment/([0-9]+)', DeleteComment),
                               ('/logout', LogoutHandler),
                               ('/credits', CreditsHandler)
                               ],
                              debug=True)
