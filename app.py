from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps
import os
from dotenv import load_dotenv

# Carregar as variáveis de ambiente do arquivo .env
load_dotenv()

app = Flask(__name__)

# Configurando a conexão PostgreSQL a partir das variáveis de ambiente
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.environ['POSTGRES_USER']}:{os.environ['POSTGRES_PASSWORD']}@{os.environ['POSTGRES_HOST']}/{os.environ['POSTGRES_DB']}"
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Modelo de usuário (Tabela no PostgreSQL)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Criar banco de dados e tabelas, se necessário
with app.app_context():
    db.create_all()

# Lista de usuários permitidos
ALLOWED_USERS = ['murillo', 'julio']

# Decorador para proteger rotas com JWT via cookie e verificar se o usuário é permitido
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('jwt_token')

        if not token:
            return redirect(url_for('login', message="Faça login primeiro!"))

        try:
            # Decodifica o token usando a chave secreta
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
            
            # Verifica se o usuário tem permissão para acessar a rota
            if current_user.lower() not in ALLOWED_USERS:
                return render_template('login.html', message="Acesso negado: usuário sem permissão.")

        except jwt.ExpiredSignatureError:
            return redirect(url_for('login', message="Token expirado, faça login novamente."))
        except jwt.InvalidTokenError:
            return redirect(url_for('login', message="Token inválido, faça login novamente."))

        return f(current_user, *args, **kwargs)

    return decorated

# Página de Cadastro de Usuário
@app.route('/', methods=['GET', 'POST'])
def register():
    message = request.args.get('message')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verificar se o usuário já existe
        if User.query.filter_by(username=username).first():
            return render_template('register.html', message="Usuário já existe!")

        # Criptografar a senha
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Criar novo usuário
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login', message="Usuário cadastrado com sucesso!"))

    return render_template('register.html', message=message)

# Página de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = request.args.get('message')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verificar se o usuário existe
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # Gera o token JWT
            token = jwt.encode({
                'username': username,
                'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm="HS256")

            # Adicionando o print para verificar o token gerado
            print(f"JWT Token Gerado: {token}")

            # Redireciona para a rota protegida com o token JWT salvo no cookie
            try:
                resp = make_response(redirect(url_for('protected')))
                resp.set_cookie('jwt_token', token, httponly=True)
                return resp
            except Exception as e:
                print(f"Erro ao redirecionar para a rota protegida: {e}")
                return render_template('login.html', message="Erro ao redirecionar.")
        else:
            return render_template('login.html', message="Credenciais inválidas!")

    return render_template('login.html', message=message)

# Rota protegida
@app.route('/protected')
@token_required
def protected(current_user):
    return render_template('protected.html', user=current_user)

# Logout (limpar o cookie JWT)
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('jwt_token', '', expires=0)  # Remove o cookie
    return resp

if __name__ == '__main__':
    app.run(debug=True)
