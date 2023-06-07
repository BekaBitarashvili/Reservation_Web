from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, LoginManager, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eatapp_database.db'
app.config['SECRET_KEY'] = 'Bitara123@'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), nullable=True, unique=True)
    email = db.Column(db.String(60), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)


class RegisterForm(FlaskForm):
    email = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "ელ-ფოსტა"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "პაროლი"})

    username = StringField(validators=[
        InputRequired(), Length(min=2, max=20)], render_kw={"placeholder": "კომპანია"})

    submit = SubmitField('რეგისტრაცია')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()

        if existing_user_email:
            raise ValidationError(
                'ასეთი უკვე არსებობს, სხვა აირჩიე.')


class LoginForm(FlaskForm):
    email = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "ელ-ფოსტა"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "პაროლი"})

    submit = SubmitField('დააჭირე')


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = User.query.filter_by(email=form.email.data).first()
        if email:
            login_user(email)
            return redirect(url_for('dashboard'))
    return render_template("login.html", form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_list = User.query.all()
    form = User()
    return render_template("dashboard.html", form=form, user_list=user_list)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password, username=form.username.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html", form=form)


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


@app.errorhandler(404)
def page_not_found():
    return "ERROR 404"


if __name__ == "__main__":
    app.run(debug=True)
