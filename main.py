import webapp2
import cgi
import jinja2
import os
import hashutils
from google.appengine.ext import db

# set up jinja
template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))

# a list of movies that nobody should be allowed to watch
terrible_movies = [
    "Gigli",
    "Star Wars Episode 1: Attack of the Clones",
    "Paul Blart: Mall Cop 2",
    "Nine Lives"
]

class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)

def get_user_by_name(name):
    users = db.GqlQuery('SELECT * FROM User WHERE username = %s', name)
    if users:
        return users.get()
    return None

class Movie(db.Model):
    title = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    watched = db.BooleanProperty(required = True, default = False)
    rating = db.StringProperty()
# end of Movie

allowed_routes = (
    '/login',
    '/register',
    '/logout',
)


class Handler(webapp2.RequestHandler):
    """ A base RequestHandler class for our app.
        The other handlers inherit form this one.
    """

    def renderError(self, error_code):
        """ Sends an HTTP error code and a generic "oops!" message to the client. """

        self.error(error_code)
        self.response.write("Oops! Something went wrong.")

    def login_user(self, user):
        user_id = user.key().id()
        self.set_secure_cookie('user_id', str(user_id))

    def log_out_user(self):
        self.set_secure_cookie('user_id', '')

    def set_secure_cookie(self, name, value):
        cookie_val = hashutils.make_secure_val(value)
        self.response.headers.add_header(
            'Set-Cookie',
            # user_id=ahamilton|56yge34..; Path=/
            '{name}={val}; Path=/'.format(
                name=name,
                val=cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return hashutils.check_secure_val(cookie_val)
        return None

    def initialize(self, *a, **kw):
        # check if user is logged in.
        # if not, redirect to /login
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))
        # if uid:
        #     self.user = User.get_by_id(int(uid))
        # else:
        #     self.user = uid
        # uid = None -> self.user = None
        # uid = '48' -> self.user = <User id: 48>

        if not self.user and self.request.path not in allowed_routes:
            self.redirect('/login')
            return

class LoginHandler(Handler):
    def render_login_form(self, error=''):
        t = jinja_env.get_template('login.html')
        content = t.render(error=error)
        self.response.write(content)

    def get(self):
        self.render_login_form()

    def post(self):
        submitted_username = self.request.get('username')
        submitted_password = self.request.get('password')

        user = get_user_by_name(submitted_username)
        if not user:
            self.render_login_form(
                error='Invalid User')
        elif not hashutils.valid_pw(submitted_password, user.pw_hash):
            self.render_login_form(
                error='Invalid Password')
        else:
            self.login_user(user)
            self.redirect('/')

class Index(Handler):
    """ Handles requests coming in to '/' (the root of our site)
        e.g. www.flicklist.com/
    """

    def get(self):
        unwatched_movies = db.GqlQuery("SELECT * FROM Movie where watched = False")
        t = jinja_env.get_template("frontpage.html")
        content = t.render(
                        movies = unwatched_movies,
                        error = self.request.get("error"))
        self.response.write(content)

class AddMovie(Handler):
    """ Handles requests coming in to '/add'
        e.g. www.flicklist.com/add
    """

    def post(self):
        new_movie_title = self.request.get("new-movie")

        # if the user typed nothing at all, redirect and yell at them
        if (not new_movie_title) or (new_movie_title.strip() == ""):
            error = "Please specify the movie you want to add."
            self.redirect("/?error=" + cgi.escape(error))

        # if the user wants to add a terrible movie, redirect and yell at them
        if new_movie_title in terrible_movies:
            error = "Trust me, you don't want to add '{0}' to your Watchlist.".format(new_movie_title)
            self.redirect("/?error=" + cgi.escape(error, quote=True))

        # 'escape' the user's input so that if they typed HTML, it doesn't mess up our site
        new_movie_title_escaped = cgi.escape(new_movie_title, quote=True)

        # construct a movie object for the new movie
        movie = Movie(title = new_movie_title_escaped)
        movie.put()

        # render the confirmation message
        t = jinja_env.get_template("add-confirmation.html")
        content = t.render(movie = movie)
        self.response.write(content)


class WatchedMovie(Handler):
    """ Handles requests coming in to '/watched-it'
        e.g. www.flicklist.com/watched-it
    """

    def renderError(self, error_code):
        self.error(error_code)
        self.response.write("Oops! Something went wrong.")


    def post(self):
        watched_movie_id = self.request.get("watched-movie")

        watched_movie = Movie.get_by_id( int(watched_movie_id) )

        # if we can't find the movie, reject.
        if not watched_movie:
            self.renderError(400)
            return

        # update the movie's ".watched" property to True
        watched_movie.watched = True
        watched_movie.put()

        # render confirmation page
        t = jinja_env.get_template("watched-it-confirmation.html")
        content = t.render(movie = watched_movie)
        self.response.write(content)


class MovieRatings(Handler):

    def get(self):
        watched_movies = db.GqlQuery("SELECT * FROM Movie where watched = True order by created desc")
        t = jinja_env.get_template("ratings.html")
        content = t.render(movies = watched_movies)
        self.response.write(content)

    def post(self):
        rating = self.request.get("rating")
        movie_id = self.request.get("movie")

        movie = Movie.get_by_id( int(movie_id) )

        if movie and rating:
            movie.rating = rating
            movie.put()

            # render confirmation
            t = jinja_env.get_template("rating-confirmation.html")
            content = t.render(movie = movie)
            self.response.write(content)
        else:
            self.renderError(400)


app = webapp2.WSGIApplication([
    ('/', Index),
    ('/add', AddMovie),
    ('/watched-it', WatchedMovie),
    ('/ratings', MovieRatings)
], debug=True)
