from flask import Flask, render_template, redirect, url_for, request, flash,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    todos = db.relationship('Todo', backref='user', lazy=True)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    is_completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash(f'Username already exists!', 'danger')
            return jsonify({'message': 'Username already exists'}), 400
        else:
            new_user = User(username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            flash(f'Your account has been created successfully! Please log in.', 'success')

            return redirect(url_for('login'))

    return render_template('register.html')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f'Logged in successfully!', 'success')
            return redirect(url_for('todos'))
        flash(f'Invalid username or password!', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash(f'You were successfully logged out.','success')
    return redirect(url_for('login'))

@app.route('/todos', methods=['GET', 'POST'])
@login_required
def todos():
    if request.method == 'POST':
        title = request.form['title']
        new_todo = Todo(title=title, user_id=current_user.id)
        db.session.add(new_todo)
        db.session.commit()

    todos = Todo.query.filter_by(user_id=current_user.id).all()
    return render_template('todos.html', todos=todos)


@app.route('/todos/update/<int:todo_id>', methods=['POST'])
@login_required
def update_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    todo.is_completed = not todo.is_completed
    db.session.commit()
    return redirect(url_for('todos'))


@app.route('/todos/delete/<int:todo_id>', methods=['POST'])
@login_required
def delete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('todos'))

with app.app_context():
    db.create_all()
if __name__ == '__main__':

    app.run(debug=True)
