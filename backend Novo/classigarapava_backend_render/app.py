import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

# Configurações
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'minha-chave-secreta-super-segura-classigarapava-2025')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///classigarapava.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar extensões
db = SQLAlchemy(app)
CORS(app)

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    user_type = db.Column(db.String(20), default='cliente')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Empresa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    descricao = db.Column(db.Text)
    categoria = db.Column(db.String(100))
    cidade = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pendente')
    destaque = db.Column(db.Boolean, default=False)
    avaliacao = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Decorador de autenticação
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token é necessário!'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token inválido!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Rotas
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'message': 'API Classigarapava funcionando!'})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'message': 'Email e senha são obrigatórios'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password_hash, password):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'token': token,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'user_type': user.user_type
            }
        })
    
    return jsonify({'message': 'Credenciais inválidas'}), 401

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    
    if not email or not password or not name:
        return jsonify({'message': 'Todos os campos são obrigatórios'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email já cadastrado'}), 400
    
    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        name=name
    )
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'Usuário criado com sucesso'}), 201

@app.route('/api/empresas', methods=['GET'])
def get_empresas():
    empresas = Empresa.query.all()
    return jsonify([{
        'id': e.id,
        'nome': e.nome,
        'descricao': e.descricao,
        'categoria': e.categoria,
        'cidade': e.cidade,
        'status': e.status,
        'destaque': e.destaque,
        'avaliacao': e.avaliacao,
        'created_at': e.created_at.isoformat() if e.created_at else None
    } for e in empresas])

@app.route('/api/empresas', methods=['POST'])
@token_required
def create_empresa(current_user):
    data = request.get_json()
    
    empresa = Empresa(
        nome=data.get('nome'),
        descricao=data.get('descricao'),
        categoria=data.get('categoria'),
        cidade=data.get('cidade')
    )
    
    db.session.add(empresa)
    db.session.commit()
    
    return jsonify({'message': 'Empresa criada com sucesso', 'id': empresa.id}), 201

@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    if current_user.user_type != 'admin':
        return jsonify({'message': 'Acesso negado'}), 403
    
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'email': u.email,
        'name': u.name,
        'user_type': u.user_type,
        'created_at': u.created_at.isoformat() if u.created_at else None
    } for u in users])

# Criar dados de exemplo
def create_sample_data():
    # Criar usuário admin
    admin = User.query.filter_by(email='admin@classigarapava.com.br').first()
    if not admin:
        admin = User(
            email='admin@classigarapava.com.br',
            password_hash=generate_password_hash('admin123'),
            name='Administrador',
            user_type='admin'
        )
        db.session.add(admin)
    
    # Criar empresas de exemplo
    if Empresa.query.count() == 0:
        empresas = [
            Empresa(nome='Tech Solutions Ltda', descricao='Empresa de tecnologia', categoria='Tecnologia', cidade='Guarapuava', status='aprovada', destaque=True, avaliacao=4.8),
            Empresa(nome='Construtora Silva & Cia', descricao='Construção civil', categoria='Construção', cidade='Guarapuava', status='pendente', avaliacao=0.0),
            Empresa(nome='Clínica Saúde Total', descricao='Clínica médica', categoria='Saúde', cidade='Guarapuava', status='aprovada', avaliacao=4.5),
            Empresa(nome='Auto Mecânica Central', descricao='Serviços automotivos', categoria='Automotivo', cidade='Guarapuava', status='rejeitada', avaliacao=0.0)
        ]
        
        for empresa in empresas:
            db.session.add(empresa)
    
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_sample_data()
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

