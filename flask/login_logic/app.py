import os
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
basedir = os.path.abspath(os.path.dirname(__file__)) # 현재 작업 디렉토리에 database.db 파일을 생성하도록 설정
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "database.db")}' # 데이터베이스 설정
app.config['SECRET_KEY'] = 'thisisasecretkey' # 시크릿 키 설정
db = SQLAlchemy(app) # 데이터베이스 설정

login_manager = LoginManager() # 로그인 매니저 설정
login_manager.init_app(app) # 로그인 매니저 초기화
login_manager.login_view = "login" # 로그인 페이지 설정

@login_manager.user_loader # 사용자 로드 함수 설정
def load_user(user_id):
    return User.query.get(int(user_id)) # 사용자를 데이터베이스에서 불러오기


class User(db.Model, UserMixin): # UserMixin을 상속받아서 User 클래스를 정의
    id = db.Column(db.Integer, primary_key=True) # id 필드를 정의
    username = db.Column(db.String(20), nullable=False, unique=True) # username 필드를 정의
    password = db.Column(db.String(80), nullable=False) # password 필드를 정의

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"}) # username 필드를 정의

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"}) # password 필드를 정의

    submit = SubmitField("Register") # submit 필드를 정의

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first() # 중복 확인
         
        if existing_user_username: # 중복이 존재한다
            raise ValidationError("That username is already exists. Please choose a different one.")  # 에러 발생

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"}) # username 필드를 정의

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"}) # password 필드를 정의

    submit = SubmitField("Login") # submit 필드를 정의

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit(): # 폼이 제출되었을 때
        user = User.query.filter_by(username=form.username.data).first() # 사용자가 존재하는지 확인
        if user: # 사용자가 존재한다    
            if bcrypt.check_password_hash(user.password, form.password.data): # 비밀번호가 일치하는지 확인
                login_user(user) # 사용자 로그인
                return redirect(url_for('dashboard')) # 대시보드로 리다이렉트
    return render_template('login.html', form=form) # 로그인 페이지 렌더링

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit(): # 폼이 제출되었을 때
        hashed_password = bcrypt.generate_password_hash(form.password.data) # 비밀번호를 해싱
        new_user = User(username=form.username.data, password=hashed_password) # 새로운 사용자 생성
        db.session.add(new_user) # 데이터베이스에 추가
        db.session.commit() # 데이터베이스에 반영
        return redirect(url_for('login')) # 로그인 페이지로 리다이렉트
    return render_template('register.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
