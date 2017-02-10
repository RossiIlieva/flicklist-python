import webapp2
import cgi
import jinja2
import os
from google.appengine.ext import db


class Movie(db.Model):
    title = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    watched = db.BooleanProperty(required=True, default=False)
    rating = db.StringProperty()

# movie = Movie(title='Kung Fu Panda')
# movie.created set for us
# movie.watched -> False
# movie.rating -> None

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


def getUnwatchedMovies():
    """ Returns the list of movies the user wants to watch (but hasnt yet) """

    # for now, we are just pretending
    movies = db.GqlQuery('SELECT * FROM Movie WHERE watched = False')
    return movies


def getWatchedMovies():
    """ Returns the list of movies the user has already watched """

    return []


class Handler(webapp2.RequestHandler):
    """ A base RequestHandler class for our app.
        The other handlers inherit form this one.
    """

    def renderError(self, error_code):
        """ Sends an HTTP error code and a generic "oops!" message to the client. """

        self.error(error_code)
        self.response.write("Oops! Something went wrong.")


class Index(Handler):
    """ Handles requests coming in to '/' (the root of our site)
        e.g. www.flicklist.com/
    """

    def get(self):
        t = jinja_env.get_template("frontpage.html")
        error = cgi.escape(self.request.get("error"), quote=True)
        content = t.render(movies=getUnwatchedMovies(), error=error)
        self.response.write(content)

class AddMovie(Handler):
    """ Handles requests coming in to '/add'
        e.g. www.flicklist.com/add
    """

    def post(self):
        new_movie = self.request.get("new-movie")

        # if the user typed nothing at all, redirect and yell at them
        if (not new_movie) or (new_movie.strip() == ""):
            error = "Please specify the movie you want to add."
            self.redirect("/?error=" + error)

        # if the user wants to add a terrible movie, redirect and yell at them
        if new_movie in terrible_movies:
            error = "Trust me, you don't want to add '{0}' to your Watchlist.".format(new_movie)
            self.redirect("/?error=" + error)

        movie = Movie(title=new_movie)
        movie.put()

        # render the confirmation message
        t = jinja_env.get_template("add-confirmation.html")
        content = t.render(movie=movie)
        self.response.write(content)


class WatchedMovie(Handler):
    """ Handles requests coming in to '/watched-it'
        e.g. www.flicklist.com/watched-it
    """

    def renderError(self, error_code):
        self.error(error_code)
        self.response.write("Oops! Something went wrong.")


    def post(self):
        watched_movie = self.request.get("watched-movie")

        # if the movie movie is just whitespace (or nonexistant), reject.
        # (we didn't check for this last time--only checked in the AddMovie handler--but we probably should have!)
        if not watched_movie or watched_movie.strip() == "":
            self.renderError(400)
            return

        movie = Movie.get_by_id(int(watched_movie))
        if not movie:
            self.renderError(404)
        movie.watched = True
        movie.put()


        # render confirmation page
        t = jinja_env.get_template("watched-it-confirmation.html")
        content = t.render(movie=movie)
        self.response.write(content)


class MovieRatings(Handler):

    def get(self):
        t = jinja_env.get_template("ratings.html")
        content = t.render(movies = getWatchedMovies())
        self.response.write(content)

    def post(self):
        movie = self.request.get("movie")
        rating = self.request.get("rating")

        if movie and rating:
            t = jinja_env.get_template("rating-confirmation.html")
            content = t.render(movie = movie, rating = rating)
            self.response.write(content)
        else:
            self.renderError(400)

class MovieDetail(Handler):
    def get(self, movie_id):
        movie = Movie.get_by_id(int(movie_id))
        if not movie:
            self.renderError(404)

        t = jinja_env.get_template('movie_detail.html')
        content = t.render(movie=movie)

        self.response.write(content)

app = webapp2.WSGIApplication([
    ('/', Index),
    ('/add', AddMovie),
    ('/watched-it', WatchedMovie),
    ('/ratings', MovieRatings),
    webapp2.Route('/movies/<movie_id:\d+>', MovieDetail),
], debug=True)
