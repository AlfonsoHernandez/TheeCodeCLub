import os
import re
import random
import hashlib
import hmac
from string import letters
from passlib.hash import pbkdf2_sha256

import webapp2
import jinja2

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = "theecodeclub"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class AppHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
    
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
    
        self.user = uid and User.by_id(int(uid))

#---------------------------------------------------------------------

def lessons_key(group = 'none'):
    return ndb.Key('lessons', group)

class Lesson(ndb.Model):
    title = ndb.StringProperty(required = True)
    short_description = ndb.TextProperty(required = True)
    long_description = ndb.TextProperty(required = True)
    #requirements = ndb.ListProperty(ndb.Text)
    jsfiddle = ndb.StringProperty(required = True)

    @classmethod
    def add(cls,project_id, title, short_description, long_description, jsfiddle):
        return Lesson(id = project_id,
                    title = title,
                    short_description = short_description,
                    long_description = long_description,
                    jsfiddle = jsfiddle)

#---------------------------------------------------------------------
#USER

def make_pw_hash(password):
    h = pbkdf2_sha256.hash(password)
    return h

def validate_pw(password, hash):
    return pbkdf2_sha256.verify(password, hash)

def  users_key(group = 'None'):
    return ndb.Key('users', group)

class User(ndb.Model):
    first_name = ndb.StringProperty(required = True)
    last_name = ndb.StringProperty(required = True)
    user_name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()
    isAdmin = ndb.BooleanProperty(required = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, first_name):
        u = User.query().filter('first_name =', first_name).get()
        return u

    @classmethod
    def by_last_name(cls, last_name):
        u = User.query().filter('last_name =', last_name).get()
        return u

    @classmethod
    def by_user_name(cls, user_name):
        u = User.query().filter(User.user_name == user_name).get()
        return u

    @classmethod
    def by_Admin(cls, isAdmin):
        u = User.query().filter('isAdmin =', isAdmin).get()
        return u

    @classmethod
    def register(cls, first_name, last_name, user_name, pw, email = None, isAdmin = False):
        pw_hash = make_pw_hash(pw)
        if(user_name == "max"):
            isAdmin = True
        return User(parent = users_key(),
                    first_name = first_name,
                    last_name = last_name,
                    user_name = user_name,
                    pw_hash = pw_hash,
                    email = email,
                    isAdmin = isAdmin)
    @classmethod
    def login(cls, user_name, pw):
        u = cls.by_user_name(user_name)
        if u and validate_pw(pw, u.pw_hash):
            return u
#---------------------------------------------------------------

class Login(AppHandler):
    def get(self):
        if self.user:
            self.redirect("/Home")
        else:
            self.render('front.html')

    def post(self):
        user_name = self.request.get('user_name')
        password = self.request.get('password')

        u = User.login(user_name, password)
        if u:
            self.login(u)
            self.redirect('/Home')
        else:
            error_message = 'Invalid Login, please try again.'
            self.render('front.html', error = error_message, user_name = user_name)

class Logout(AppHandler):
    def get(self):
        self.logout()
        self.redirect('/')


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_user_name(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class SignUpHandler(AppHandler):
    def get(self):
        self.render('signup.html')
    
    def post(self):
        have_error = False
        self.first_name = self.request.get('first_name')
        self.first_name = self.first_name.title()

        self.last_name = self.request.get('last_name')
        self.last_name = self.last_name.title()

        self.user_name = self.request.get('user_name')
        self.user_name = self.user_name.lower()

        self.password = self.request.get('password')

        self.verify_password = self.request.get('verify_password')

        self.email = self.request.get('email')
        self.email = self.email.lower()

        self.signup_code = self.request.get('signup_code')

        self.isAdmin = False

        params = dict(user_name = self.user_name, email = self.email)

        if not valid_user_name(self.user_name):
            params['error_username'] = "Username invalid."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Password invalid."
            have_error = True
        elif self.password != self.verify_password:
            params['error_verify_password'] = "Passwords do not match."
            have_error = True

        if not valid_email(self.email):
            params['error_username'] = "Email invalid."
            have_error = True

        self.done()

        def done(self, *a, **kw):
            raise NotImplementedError

class LessonAddHandler(AppHandler):
    def get(self):
        self.render('add_lesson.html')
    def post(self):
        have_error = False

        self.title = self.request.get('title')
        self.title = self.title.title()

        self.project_id = self.request.get('project_id')

        self.short_description = self.request.get('short')

        self.long_description = self.request.get('long')

        self.jsfiddle = self.request.get('jsfiddle')

        self.done()

        def done(self, *a, **kw):
            raise NotImplementedError


class SignUp(SignUpHandler):
    def done(self):
        u = User.by_user_name(self.user_name)
        if u:
            error_message = 'Username already exists.'
            self.render('signup.html', error = error_message)
        elif self.signup_code != "Web2017":
            error_message = "Sign Up code not valid."
            self.render('signup.html', error = error_message)
        else:
            u = User.register(self.first_name, self.last_name, self.user_name, self.password, self.email, self.isAdmin)
            u.put()

            self.login(u)
            self.redirect('/Home')

class AddLesson(LessonAddHandler):
    def done(self):
        lesson = Lesson.add(self.project_id, self.title, self.short_description, self.long_description, self.jsfiddle)
        lesson.put()

        self.redirect('/Admin')

class Home(AppHandler):
    def get(self):
        if self.user:
            self.render('home.html')
        else:
            self.render('front.html')

class AdminPage(AppHandler):
    def get(self):
        if self.user.isAdmin:
            students = User.query().filter(User.isAdmin == False)
            admins = User.query().filter(User.isAdmin == True)
            self.render('admin.html', Students = students, Admins = admins)
        else:
            self.redirect('/Home')

class Gallery(AppHandler):
    def get(self):
        self.render('gallery.html')

class Lessons(AppHandler):
    def get(self):
        lessons = Lesson.query()
        self.render('lessons.html', Lessons = lessons)

class LessonPage(AppHandler):
    def get(self):
        lessons = Lesson.query()
        self.render('lesson.html', Lesson = lessons)

app = webapp2.WSGIApplication([('/', Login),
                               ('/Logout', Logout), 
                               ('/SignUp', SignUp),
                               ('/Home', Home),
                               ('/Admin', AdminPage),
                               ('/Gallery', Gallery),
                               ('/Lessons', Lessons),
                               ('/AddLesson', AddLesson),
                               ('/Lesson', LessonPage),
                               ],
                              debug=True)
