from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from loginrequired import login_required

app = Flask(__name__)


app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///cuyes.db")

#index
@app.route("/", methods=["GET"])
def index():
    """ mostrar homepage """
    if request.method == "GET":
        return render_template("index.html")
    else:
        return render_template("error.html", message="Metodo get requerido.")


#ruta que direcciona al formulario de registro
@app.route("/registerform", methods=["POST"])
def pregister():
    if request.method == "POST":
        return redirect("/register")


#pagina de registro
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        username = request.form.get("username")
        pwhash = request.form.get("password")
        secpsswd = request.form.get("rpassword")

        if not username:
            return render_template("error.html", message="debes ingresar un nombre", link="/register")

        elif not pwhash:
            return render_template("error.html", message="debes ingresar una contrasena", link="/register")

        elif not secpsswd:
            return render_template("error.html", message="No has confirmado tu contrasena", link="/register")

        elif pwhash != secpsswd:
            return render_template("error.html", message="Las contrasenas no coinciden", link="/register")

        else:
            repetido = db.execute("SELECT username FROM users WHERE username = ?", request.form.get("username"))

            if not repetido:
                pwhash = generate_password_hash(pwhash)
                new = db.execute("INSERT  INTO users (username, hash) VALUES (?, ?)", username, pwhash)
                #ingreso en la base de datos exitoso
                return redirect("/login")

            else:
                return render_template("error.html", message="Ese nombre no esta disponible")

    else:
        return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            return render_template("error.html", message="No ingresaste tu nombre", link="/login")


        elif not password:
            return render_template("error.html", message="No ingresaste tu contrasena", link="/login")


        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("error.html", message="Ese usuario no lo conozco :(")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/homepage")

    else:
        #bring the form to login!
        return render_template("login.html")


#cerrar sesion
@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    # una vez cerrada la session dirigir al index
    return redirect("/")



#pagina de inicio, muestra el contenido de la pagina, requiere que
#se haya iniciado sesion
@app.route("/homepage", methods=["GET", "POST"])
@login_required
def homepage():
    if request.method == "GET":
        return render_template("homepage.html")
    else:
        return render_template("error.html", message="jejej no")



#ruta que muestra todos los servicios que hay en la base de datos
@app.route("/ayuda", methods = ["GET"])
@login_required
def ayuda():

    if request.method == "GET":

        contactos = db.execute("SELECT * FROM ayuda")
        return render_template("ayuda.html", contactos = contactos)
