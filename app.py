import bcrypt, os
import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta


app = Flask(__name__)
app.secret_key = 'your-secret-key'
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
csrf = CSRFProtect(app)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS에서 쿠키 접근 차단
    SESSION_COOKIE_SECURE=True,     # HTTPS일 때만 쿠키 전송 (개발 시 False 가능)
    SESSION_COOKIE_SAMESITE='Lax'   # 외부 사이트에서의 쿠키 전송 제한 (추천: 'Lax')
)

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)


# CSRF 토큰 예외처리
@app.errorhandler(400)
def handle_csrf_error(e):
    return render_template("error.html", message="CSRF 토큰이 유효하지 않습니다."), 400

# 관리자 확인 데코레이터 함수 생성
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        db = get_db()
        cursor = db.cursor()
        user_id = session.get('user_id')

        if not user_id:
            flash("로그인이 필요합니다.")
            return redirect(url_for('login'))

        cursor.execute("SELECT role FROM user WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user or user['role'] != 'admin':
            flash("관리자 권한이 필요합니다.")
            return redirect(url_for('dashboard'))

        return f(*args, **kwargs)
    return decorated_function

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        raw_password = request.form['password']
        hashed_pw = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt())

        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_pw))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        raw_password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(raw_password.encode('utf-8'), user['password']):
            if user['status'] == 'suspended':
                flash("휴먼 계정으로 전환된 상태입니다. 로그인할 수 없습니다.")
                return redirect(url_for('login'))
            session['user_id'] = user['id']
            session['role'] = user['role']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product WHERE is_blocked = 0")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()

    #유저 정보 로딩
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if request.method == 'POST':
        bio = request.form.get('bio', '')
        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        if len(bio) > 300:
            flash('소개글은 300자 이내여야 합니다.')
            return redirect(url_for('profile'))

        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))

        if current_pw and new_pw and confirm_pw:
            if not current_pw or not new_pw or not confirm_pw:
                flash('비밀번호 변경 시 모든 항목을 입력해야 합니다.')
                return redirect(url_for('profile'))
            
            if len(new_pw) < 8:
                flash('새 비밀번호는 최소 8자 이상이어야 합니다.')
                return redirect(url_for('profile'))

            if new_pw != confirm_pw:
                flash("새 비밀번호와 확인 비밀 번호가 일치하지 않습니다.")
                return redirect(url_for('profile'))
            
            if bcrypt.checkpw(current_pw.encode('utf-8'), current_user['password']):
                hashed_pw = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_pw, session['user_id']))
                db.commit()
                flash('비밀번호가 변경되었습니다. 다시 로그인 해주세요.')
                session.pop('user_id', None)
                return redirect(url_for('login'))
            else:
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('profile'))
        else:
            flash('프로필이 업데이트되었습니다.')

        db.commit()
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=current_user, balance=current_user['balance'])

#송금 기능
@app.route('/transfer/<target_id>', methods=['GET', 'POST'])
def transfer(target_id):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for('login'))

    sender_id = session['user_id']
    if sender_id == target_id:
        flash("본인에게는 송금할 수 없습니다.")
        return redirect(url_for('profile'))

    db = get_db()
    cursor = db.cursor()

    # 수신자 확인
    cursor.execute("SELECT username FROM user WHERE id = ?", (target_id,))
    target_user = cursor.fetchone()
    if not target_user:
        flash("존재하지 않는 사용자입니다.")
        return redirect(url_for('dashboard'))

    # 송신자 잔액 가져오기
    cursor.execute("SELECT balance FROM user WHERE id = ?", (sender_id,))
    sender_balance = cursor.fetchone()['balance']

    if request.method == 'POST':
        try:
            amount = int(request.form['amount'])
        except:
            flash("올바른 금액을 입력해주세요.")
            return redirect(url_for('transfer', target_id=target_id))

        password = request.form.get('password', '').strip()

        # 비밀번호 확인
        cursor.execute("SELECT password FROM user WHERE id = ?", (sender_id,))
        stored_hash = cursor.fetchone()['password']

        if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
            flash("Incorrect password.")
            return redirect(url_for('transfer', target_id=target_id))

        if amount <= 0:
            flash("1원 이상 입력해주세요.")
        elif amount > sender_balance:
            flash("잔액이 부족합니다.")
        else:
            tx_id = str(uuid.uuid4())
            timestamp = datetime.now().isoformat()

            try:
                with db:  # 트랜잭션 - 중간 오류 발생시 생길 수 있는 문제 수정
                    cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, sender_id))
                    cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, target_id))
                    cursor.execute("""
                        INSERT INTO transactions (id, sender_id, receiver_id, amount, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    """, (tx_id, sender_id, target_id, amount, timestamp))
                flash(f"{target_user['username']}님에게 {amount}원을 송금했습니다.")
                return redirect(url_for('transfer', target_id=target_id))
            except Exception as e:
                db.rollback()  # 예외 발생 시 수동 롤백
                flash("송금 처리 중 오류가 발생했습니다.")
                print(f"[송금 오류] {e}")

    return render_template(
        'transfer.html',
        target_id=target_id,
        target_name=target_user['username'],
        balance=sender_balance
    )



# 판매자 정보 보기
@app.route('/user/<user_id>')
def view_user_profile(user_id):
    db = get_db()
    cursor = db.cursor()

    # 판매자 정보 가져오기
    cursor.execute("SELECT id, username, bio FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        flash('해당 사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 해당 사용자가 올린 상품 리스트
    cursor.execute("SELECT id, title FROM product WHERE seller_id = ?", (user_id,))
    products = cursor.fetchall()

    return render_template('user_profile.html', user=user, products=products)




def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        price_raw = request.form['price'].strip()
        file = request.files.get('image')

        if not price_raw.isdigit():
            flash("가격은 숫자만 입력해야 합니다.")
            return redirect(url_for('new_product'))

        price = int(price_raw)

        image_path = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            ext = filename.rsplit('.', 1)[1].lower()
            ran_filename = f"{uuid.uuid4().hex}.{ext}"  # 랜덤 UUID + 확장자
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], ran_filename))
            image_path = os.path.join('uploads', ran_filename)

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id, image_path) VALUES (?, ?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'], image_path)
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product or product['is_blocked']:
        flash("해당 상품은 차단되어 접근할 수 없습니다.")
        return redirect(url_for('dashboard'))
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    elif product['is_blocked']:
        flash("해당 상품은 차단되어 접근할 수 없습니다.")
        return redirect(url_for('dashboard'))
    
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 상품 정보 수정
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('해당 상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    if product['seller_id'] != session['user_id']:
        flash('수정 권한이 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        file = request.files.get('image')
        image_path = product['image_path']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_path = os.path.join('uploads', filename)

        cursor.execute("""
            UPDATE product
            SET title = ?, description = ?, price = ?, image_path = ?
            WHERE id = ?
        """, (title, description, price, image_path, product_id))
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)

# 상품 결제하기
@app.route('/purchase/<product_id>', methods=['GET', 'POST'])
def purchase(product_id):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상품 존재 여부 확인
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("존재하지 않는 상품입니다.")
        return redirect(url_for('dashboard'))

    # 본인 상품 차단
    if product['seller_id'] == session['user_id']:
        flash("본인의 상품은 구매할 수 없습니다.")
        return redirect(url_for('dashboard'))

    # 판매 완료 여부 확인
    if product['is_sold']:
        flash("이미 판매된 상품입니다.")
        return redirect(url_for('dashboard'))

    # 구매자 잔액 확인
    buyer_id = session['user_id']
    cursor.execute("SELECT balance FROM user WHERE id = ?", (buyer_id,))
    buyer_balance = cursor.fetchone()['balance']
    price = product['price']

    if request.method == 'POST':
        # 잔액 부족 처리
        if int(buyer_balance) < int(price):
            flash("잔액이 부족합니다.")
            return redirect(url_for('purchase', product_id=product_id))

        try:
            with db:
                # 구매자 잔액 차감
                cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (price, buyer_id))
                # 판매자 잔액 증가
                cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (price, product['seller_id']))
                # 거래 기록 저장
                tx_id = str(uuid.uuid4())
                timestamp = datetime.now().isoformat()
                cursor.execute("""
                    INSERT INTO transactions (id, sender_id, receiver_id, amount, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (tx_id, buyer_id, product['seller_id'], price, timestamp))
                # 상품 판매 상태로 변경
                cursor.execute("UPDATE product SET is_sold = 1 WHERE id = ?", (product_id,))
            flash("결제가 완료되었습니다.")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.rollback()
            flash("결제 처리 중 오류가 발생했습니다.")
            print(f"[결제 오류] {e}")

    return render_template("purchase.html", product=product, balance=buyer_balance)



# 상품 삭제하기
@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('해당 상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    if product['seller_id'] != session['user_id']:
        flash('삭제 권한이 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT * FROM product
        WHERE title LIKE ? OR description LIKE ?
    """, (f'%{query}%', f'%{query}%'))
    
    results = cursor.fetchall()

    return render_template('search_results.html', query=query, results=results)

@app.route('/chat/<user_id>', methods=['GET', 'POST'])
def chat(user_id):
    if 'user_id' not in session:
        flash('로그인이 필요합니다.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상대 유저 정보
    cursor.execute("SELECT id, username FROM user WHERE id = ?", (user_id,))
    partner = cursor.fetchone()
    if not partner:
        flash("상대방을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    # 메시지 저장
    if request.method == 'POST':
        content = request.form['content']
        msg_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        cursor.execute("""
            INSERT INTO message (id, sender_id, receiver_id, content, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (msg_id, session['user_id'], user_id, content, timestamp))
        db.commit()

    # 메시지 조회 (양방향)
    cursor.execute("""
        SELECT * FROM message
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (session['user_id'], user_id, user_id, session['user_id']))
    messages = cursor.fetchall()

    return render_template('chat.html', partner=partner, messages=messages)


# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for('login'))

    target_id = request.args.get('target_id', '')
    db = get_db()
    cursor = db.cursor()

    # 사용자 이름 가져오기
    target_name = target_id
    if target_id:
        cursor.execute("SELECT username FROM user WHERE id = ?", (target_id,))
        user_result = cursor.fetchone()
        if user_result:
            target_name = user_result['username']

    if request.method == 'POST':
        reporter_id = session['user_id']
        reported_id = request.form['target_id'].strip()
        reason = request.form['reason'].strip()

        if not reported_id or not reason:
            flash("신고 대상과 사유는 필수입니다.")
            return redirect(url_for('report'))

        report_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        try:
            with db:
                cursor.execute("""
                    INSERT INTO report (id, reporter_id, reported_id, reason, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (report_id, reporter_id, reported_id, reason, timestamp))

                cursor.execute("SELECT COUNT(*) as count FROM report WHERE reported_id = ?", (reported_id,))
                count = cursor.fetchone()['count']

                cursor.execute("SELECT * FROM user WHERE id = ?", (reported_id,))
                target_user = cursor.fetchone()
                if target_user and count >= 3 and target_user['status'] != 'suspended':
                    cursor.execute("UPDATE user SET status = 'suspended' WHERE id = ?", (reported_id,))
                    flash("해당 유저는 신고 누적으로 휴먼 계정으로 전환되었습니다.")

                cursor.execute("SELECT * FROM product WHERE id = ?", (reported_id,))
                target_product = cursor.fetchone()
                if target_product and count >= 3 and not target_product['is_blocked']:
                    cursor.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (reported_id,))
                    flash("해당 상품은 신고 누적으로 차단되었습니다.")

            flash("신고가 접수되었습니다.")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.rollback()
            flash("신고 처리 중 오류가 발생했습니다.")

    return render_template('report.html', target_id=target_id, target_name=target_name)




# 관리자 페이지 (신고 내용 조회)
@app.route('/admin/reports')
@admin_required
def view_reports():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT r.id, r.reporter_id, r.target_id, r.reason
        FROM report r
        ORDER BY r.id DESC
    """)
    reports = cursor.fetchall()
    return render_template('admin_reports.html', reports=reports)

# 신고 내역 삭제
@app.route('/admin/reports/delete/<report_id>', methods=['POST'])
@admin_required
def delete_report(report_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()
    flash("신고 내역이 삭제되었습니다.")
    return redirect(url_for('view_reports'))



# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
