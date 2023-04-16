from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date, datetime
from werkzeug import exceptions
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps
from flask_gravatar import Gravatar
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b12358'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False,
                    force_lower=False, use_ssl=False, base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///blog.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# initialize the app with the extension
# db.init_app(app)
######################## Custom Decorator #################################
#test   123


def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.get_id() == '1':
            return function(*args, **kwargs)
        else:
            msg = "Access is denied for normal users."
            raise exceptions.Forbidden(description=msg)

    return wrapper_function

######################### Set tables  ####################################


class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.relationship('User', backref='blog_post')
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship('Comment', backref="blog_post")


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    posts = db.relationship('BlogPost', backref="user")
    comments = db.relationship('Comment', backref="user")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, nullable=False)
    commenter = db.relationship('User', backref='comment')
    commenter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post = db.relationship('BlogPost', backref='comment')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'))


with app.app_context():
    db.create_all()

###################### Login Manager ####################################

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)
###################### Routing functions ####################################


@app.route('/')
def get_all_posts():
    try:
        posts = db.session.execute(
            db.select(BlogPost).order_by(BlogPost.date)).scalars()

    except Exception as e:
        posts = []

    IS_ADMIN = False
    if '_user_id' in session:
        if session['_user_id'] == '1':
            IS_ADMIN = True

    return render_template("index.html", all_posts=posts, is_admin=IS_ADMIN)


@app.route('/register', methods=['GET', 'POST'])
def register():
    new_registration = RegisterForm()
    if new_registration.validate_on_submit():
        entered_email = request.form['email']
        try:
            stored_email = db.one_or_404(
                db.select(User).filter_by(email=entered_email))
            flash("You've already signed up with that email. Login instead",
                  'Already_registered_email')
            return app.redirect(url_for('login'))
        except Exception:
            new_user = User()
            new_user.name = request.form['name']
            new_user.email = entered_email
            new_user.password = generate_password_hash(
                request.form['password'], method='pbkdf2:sha256', salt_length=8)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return app.redirect(location=url_for('get_all_posts'))

    return render_template("register.html", form=new_registration)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        entered_email = request.form['email']
        entered_password = request.form['password']
        try:
            stored_user = db.session.execute(
                db.select(User).filter_by(email=entered_email)).scalar_one()
            if check_password_hash(stored_user.password, entered_password):
                login_user(stored_user)
                return app.redirect(location=url_for('get_all_posts'))
            else:
                flash("Password incorrect. Please try again!", 'Invalid Password')
                return app.redirect(location=url_for('login'))
        except Exception:
            flash("This email does not exist. Please try again!", 'not_found_email')
            return app.redirect(location=url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = db.session.execute(
        db.select(BlogPost).filter_by(id=post_id)).scalar_one()
    new_comment_form = CommentForm()
    IS_ADMIN = False
    if '_user_id' in session:
        if session['_user_id'] == '1':
            IS_ADMIN = True

    if new_comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=request.form['comment'], commenter=current_user, post=requested_post)
            db.session.add(new_comment)
            db.session.commit()

            return render_template("post.html", post=requested_post, is_admin=IS_ADMIN, form=new_comment_form)

        else:
            flash("You need to login or register to comment", 'auth to comment')
            return app.redirect(location=url_for('login'))

    return render_template("post.html", post=requested_post, is_admin=IS_ADMIN, form=new_comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return app.redirect(location=url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_edit=False)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    post = db.session.execute(
        db.select(BlogPost).filter_by(id=post_id)).scalar_one()
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return app.redirect(location=url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = db.session.execute(
        db.select(BlogPost).filter_by(id=post_id)).scalar_one()
    db.session.delete(post_to_delete)
    db.session.commit()
    return app.redirect(location=url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
