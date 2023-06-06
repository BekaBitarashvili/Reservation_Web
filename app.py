from flask import Flask, render_template, url_for

app = Flask(__name__)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/features')
def features():
    return render_template("features.html")


@app.route('/costumers')
def costumers():
    return render_template("costumers.html")


@app.route('/pricing')
def pricing():
    return render_template("pricing.html")


@app.route('/contact')
def contact():
    return render_template("contact.html")


@app.route('/resources')
def resources():
    return render_template("resources.html")


@app.route('/login')
def login():
    return render_template("login.html")


if __name__ == "__main__":
    app.run(debug=True)
