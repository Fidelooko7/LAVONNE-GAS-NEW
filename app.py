from flask import Response, Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime, date, timedelta
from pathlib import Path
import sqlite3, os, secrets, hmac
import re
import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
if os.environ.get('RENDER') and not DATABASE_URL:
    raise RuntimeError('DATABASE_URL is required on Render; refusing to start with a separate SQLite database.')
USE_POSTGRES = bool(DATABASE_URL)
if USE_POSTGRES and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = 'postgresql://' + DATABASE_URL[len('postgres://'):]
DB_INTEGRITY_ERROR = psycopg.IntegrityError if USE_POSTGRES else sqlite3.IntegrityError

ROOT = Path(__file__).resolve().parent
DB = ROOT / 'instance' / 'lavonne_v3.db'
UPLOADS = ROOT / 'static' / 'uploads'
UPLOADS.mkdir(parents=True, exist_ok=True)
DB.parent.mkdir(parents=True, exist_ok=True)
app = Flask(__name__)
SECRET_FILE = DB.parent / 'secret_key'
if not SECRET_FILE.exists():
    SECRET_FILE.write_text(secrets.token_urlsafe(48))
app.secret_key = os.environ.get('LAVONNE_SECRET') or SECRET_FILE.read_text().strip()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
ALLOWED = {'png','jpg','jpeg','webp'}

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','employee')), active INTEGER DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, brand TEXT NOT NULL, size TEXT NOT NULL, sell_price REAL NOT NULL DEFAULT 0, buy_cost REAL NOT NULL DEFAULT 0, image TEXT, active INTEGER DEFAULT 1, UNIQUE(brand,size));
CREATE TABLE IF NOT EXISTS stock(id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL UNIQUE REFERENCES products(id), full_qty INTEGER NOT NULL DEFAULT 0, empty_qty INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL, address TEXT DEFAULT '', created_at TEXT NOT NULL, password_hash TEXT DEFAULT '', profile_image TEXT DEFAULT '', active INTEGER DEFAULT 1, last_login TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id), customer_id INTEGER REFERENCES customers(id), qty INTEGER NOT NULL, unit_price REAL NOT NULL, unit_cost REAL NOT NULL, total REAL NOT NULL, paid REAL NOT NULL, payment_method TEXT NOT NULL, sale_date TEXT NOT NULL, user_id INTEGER REFERENCES users(id), note TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS debts(id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id), sale_id INTEGER REFERENCES sales(id), original REAL NOT NULL, due_date TEXT NOT NULL, issued_at TEXT NOT NULL, note TEXT DEFAULT '', created_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS debt_payments(id INTEGER PRIMARY KEY, debt_id INTEGER NOT NULL REFERENCES debts(id), amount REAL NOT NULL, method TEXT NOT NULL, paid_at TEXT NOT NULL, recorded_by INTEGER REFERENCES users(id), note TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS purchases(id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id), qty INTEGER NOT NULL, unit_cost REAL NOT NULL, total REAL NOT NULL, purchase_date TEXT NOT NULL, supplier TEXT DEFAULT '', user_id INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY, title TEXT NOT NULL, amount REAL NOT NULL, expense_date TEXT NOT NULL, note TEXT DEFAULT '', user_id INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id), customer_name TEXT NOT NULL, phone TEXT NOT NULL, address TEXT DEFAULT '', qty INTEGER NOT NULL, unit_price REAL NOT NULL, fulfillment TEXT NOT NULL, payment_choice TEXT NOT NULL, payment_status TEXT NOT NULL DEFAULT 'unverified', order_status TEXT NOT NULL DEFAULT 'new', created_at TEXT NOT NULL, handled_by INTEGER REFERENCES users(id), delivered_by INTEGER REFERENCES users(id), delivery_note TEXT DEFAULT '', customer_id INTEGER REFERENCES customers(id));
CREATE TABLE IF NOT EXISTS news(id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, image TEXT, tag TEXT DEFAULT 'Info', important INTEGER DEFAULT 0, created_at TEXT NOT NULL, created_by INTEGER REFERENCES users(id), active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS stock_confirmations(id INTEGER PRIMARY KEY, confirm_date TEXT NOT NULL, product_id INTEGER NOT NULL REFERENCES products(id), full_qty INTEGER NOT NULL, empty_qty INTEGER NOT NULL, confirmed_by INTEGER REFERENCES users(id), admin_confirmed INTEGER DEFAULT 0, admin_id INTEGER REFERENCES users(id), note TEXT DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cylinder_deposits(id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id), product_id INTEGER REFERENCES products(id), qty INTEGER NOT NULL DEFAULT 1, deposit_amount REAL DEFAULT 0, status TEXT NOT NULL DEFAULT 'outstanding', issued_at TEXT NOT NULL, returned_at TEXT, note TEXT DEFAULT '', created_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL);
'''
class PostgreSQLCompat:
    """Small adapter so existing ? placeholders and connection calls keep working."""
    def __init__(self):
        self.raw = psycopg.connect(DATABASE_URL, row_factory=dict_row)

    def execute(self, query, params=()):
        # The app's SQL statements use ? only as parameter placeholders.
        return self.raw.execute(query.replace('?', '%s'), params)

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()


def db():
    if USE_POSTGRES:
        return PostgreSQLCompat()
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c


def init_db():
    if USE_POSTGRES:
        # PostgreSQL schema and migrated records are created separately.
        # Never run the SQLite schema or alter production tables at startup.
        c = db()
        required = {
            'users', 'products', 'stock', 'customers', 'sales', 'debts',
            'debt_payments', 'purchases', 'expenses', 'orders', 'news',
            'stock_confirmations', 'cylinder_deposits', 'settings', 'audit'
        }
        rows = c.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema='public' AND table_type='BASE TABLE'"
        ).fetchall()
        present = {r['table_name'] for r in rows}
        missing = sorted(required - present)
        c.close()
        if missing:
            raise RuntimeError(
                'PostgreSQL database is missing required tables: ' + ', '.join(missing)
            )
        return

    c=db()
    c.executescript(SCHEMA)
    columns = [r['name'] for r in c.execute('PRAGMA table_info(orders)').fetchall()]
    if 'customer_id' not in columns:
        c.execute('ALTER TABLE orders ADD COLUMN customer_id INTEGER REFERENCES customers(id)')
    c.commit()
    c.close()

init_db()

def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
def today(): return date.today().isoformat()
def money(v): return round(float(v or 0),2)
def audit(action, details):
    if session.get('uid'):
        c=db(); c.execute('INSERT INTO audit(user_id,action,details,created_at) VALUES(?,?,?,?)',(session['uid'],action,details,now())); c.commit(); c.close()
def current_user():
    if not session.get('uid'): return None
    c=db(); u=c.execute('SELECT id,username,role FROM users WHERE id=? AND active=1',(session['uid'],)).fetchone(); c.close(); return u
@app.context_processor
def inject():
    return {'me':current_user(),'today':today(),'money':lambda x:f'{money(x):,.2f}'}
def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if not current_user(): return redirect(url_for('login',next=request.path))
        return f(*a,**k)
    return w
def admin_required(f):
    @wraps(f)
    def w(*a,**k):
        u=current_user()
        if not u: return redirect(url_for('login'))
        if u['role']!='admin': abort(403)
        return f(*a,**k)
    return w
def get_products(active_only=False):
    c=db(); q='SELECT p.*, COALESCE(s.full_qty,0) full_qty, COALESCE(s.empty_qty,0) empty_qty FROM products p LEFT JOIN stock s ON s.product_id=p.id'
    if active_only:q+=' WHERE p.active=1'
    rows=c.execute(q+' ORDER BY p.brand,p.size').fetchall(); c.close(); return rows
def balance(c, debt_id):
    r=c.execute('SELECT d.original-COALESCE(SUM(p.amount),0) bal FROM debts d LEFT JOIN debt_payments p ON p.debt_id=d.id WHERE d.id=? GROUP BY d.id',(debt_id,)).fetchone(); return money(r['bal'] if r else 0)

@app.route('/')
def home():
    products=get_products(True)
    c=db(); news=c.execute("SELECT * FROM news WHERE active=1 ORDER BY important DESC, id DESC LIMIT 6").fetchall(); c.close(); return render_template("store.html",products=products,news=news)

@app.route('/customer/register', methods=['GET','POST'])
def customer_register():
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        phone = request.form.get('phone','').strip()
        address = request.form.get('address','').strip()
        password = request.form.get('password','')
        confirm = request.form.get('confirm_password','')

        if not name or not phone or not password:
            flash('Name, phone number and password are required.','error')
        elif len(password) < 8:
            flash('Password must contain at least 8 characters.','error')
        elif password != confirm:
            flash('Passwords do not match.','error')
        else:
            c = db()
            existing = c.execute(
                'SELECT * FROM customers WHERE phone=? ORDER BY id LIMIT 1',
                (phone,)
            ).fetchone()

            if existing and existing['password_hash']:
                c.close()
                flash('An account already exists. Please log in.','error')
            elif existing:
                c.execute(
                    'UPDATE customers SET name=?,address=?,password_hash=?,active=1 WHERE id=?',
                    (name,address,generate_password_hash(password),existing['id'])
                )
                cid = existing['id']
                c.commit()
                c.close()
                session.clear()
                session['customer_id'] = cid
                session.permanent = True
                return redirect(url_for('customer_dashboard'))
            else:
                cid = c.execute(
                    'INSERT INTO customers(name,phone,address,password_hash,created_at) VALUES(?,?,?,?,?) RETURNING id',
                    (name,phone,address,generate_password_hash(password),now())
                ).fetchone()['id']
                c.commit()
                c.close()
                session.clear()
                session['customer_id'] = cid
                session.permanent = True
                return redirect(url_for('customer_dashboard'))

    return render_template('customer_register.html')


@app.route('/customer/login', methods=['GET','POST'])
def customer_login():
    if request.method == 'POST':
        phone = request.form.get('phone','').strip()
        password = request.form.get('password','')
        c = db()
        customer = c.execute(
            'SELECT * FROM customers WHERE phone=? AND active=1 ORDER BY id LIMIT 1',
            (phone,)
        ).fetchone()

        if customer and customer['password_hash'] and check_password_hash(customer['password_hash'],password):
            c.execute('UPDATE customers SET last_login=? WHERE id=?',(now(),customer['id']))
            c.commit()
            cid = customer['id']
            c.close()
            session.clear()
            session['customer_id'] = cid
            session.permanent = True
            return redirect(url_for('customer_dashboard'))

        c.close()
        flash('Incorrect phone number or password.','error')

    return render_template('customer_login.html')


@app.route('/customer/logout')
def customer_logout():
    session.pop('customer_id',None)
    return redirect(url_for('customer_login'))


@app.route('/customer/dashboard')
def customer_dashboard():
    cid = session.get('customer_id')
    if not cid:
        return redirect(url_for('customer_login'))

    c = db()
    customer = c.execute(
        'SELECT * FROM customers WHERE id=? AND active=1',(cid,)
    ).fetchone()

    if not customer:
        c.close()
        session.pop('customer_id',None)
        return redirect(url_for('customer_login'))

    debt = c.execute("""
        SELECT COALESCE(SUM(d.original),0) -
        COALESCE((SELECT SUM(dp.amount)
                  FROM debt_payments dp
                  JOIN debts dx ON dx.id=dp.debt_id
                  WHERE dx.customer_id=?),0) AS balance
        FROM debts d WHERE d.customer_id=?
    """,(cid,cid)).fetchone()

    orders = c.execute("""
        SELECT o.*,p.brand,p.size
        FROM orders o JOIN products p ON p.id=o.product_id
        WHERE o.customer_id=?
        ORDER BY o.id DESC
    """,(cid,)).fetchall()

    payments = c.execute("""
        SELECT dp.* FROM debt_payments dp
        JOIN debts d ON d.id=dp.debt_id
        WHERE d.customer_id=?
        ORDER BY dp.id DESC
    """,(cid,)).fetchall()

    c.close()
    return render_template(
        'customer_dashboard.html',
        customer=customer,
        balance=debt['balance'] if debt else 0,
        recent_orders=orders,
        payments=payments
    )


@app.route('/customer/credentials', methods=['GET', 'POST'])
def customer_credentials():
    cid = session.get('customer_id')
    if not cid:
        return redirect(url_for('customer_login'))

    c = db()
    customer = c.execute(
        'SELECT * FROM customers WHERE id=? AND active=1', (cid,)
    ).fetchone()

    if not customer:
        c.close()
        session.pop('customer_id', None)
        return redirect(url_for('customer_login'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()

        if not name or not phone:
            flash('Name and phone number are required.', 'error')
        else:
            duplicate = c.execute(
                'SELECT id FROM customers WHERE phone=? AND id<>? LIMIT 1',
                (phone, cid)
            ).fetchone()

            if duplicate:
                flash('That phone number is already registered to another account.', 'error')
            else:
                c.execute(
                    'UPDATE customers SET name=?, phone=?, address=? WHERE id=?',
                    (name, phone, address, cid)
                )
                c.commit()
                flash('Your credentials have been updated.', 'success')
                customer = c.execute(
                    'SELECT * FROM customers WHERE id=?', (cid,)
                ).fetchone()

    c.close()
    return render_template('customer_credentials.html', customer=customer)


@app.route('/customer/change-password', methods=['GET', 'POST'])
def customer_change_password():
    cid = session.get('customer_id')
    if not cid:
        return redirect(url_for('customer_login'))

    c = db()
    customer = c.execute(
        'SELECT * FROM customers WHERE id=? AND active=1', (cid,)
    ).fetchone()

    if not customer:
        c.close()
        session.pop('customer_id', None)
        return redirect(url_for('customer_login'))

    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        if not check_password_hash(customer['password_hash'], current):
            flash('Your current password is incorrect.', 'error')
        elif len(new) < 8:
            flash('Your new password must contain at least 8 characters.', 'error')
        elif new != confirm:
            flash('The new passwords do not match.', 'error')
        else:
            c.execute(
                'UPDATE customers SET password_hash=? WHERE id=?',
                (generate_password_hash(new), cid)
            )
            c.commit()
            flash('Your password has been changed successfully.', 'success')

    c.close()
    return render_template('customer_change_password.html')


@app.route('/order',methods=['POST'])
def place_order():
    c=db()
    p=c.execute('SELECT * FROM products WHERE id=? AND active=1',(request.form.get('product_id'),)).fetchone()
    try: qty=max(1,int(request.form.get('qty','1')))
    except: qty=1

    if not p:
        c.close()
        flash('Please select an available product.','error')
        return redirect(url_for('home'))

    customer_id=session.get('customer_id')
    customer=None

    if customer_id:
        customer=c.execute('SELECT * FROM customers WHERE id=? AND active=1',(customer_id,)).fetchone()
        if not customer:
            session.pop('customer_id',None)
            customer_id=None

    if customer:
        name=customer['name']
        phone=customer['phone']
        address=customer['address'] or request.form.get('address','').strip()
        customer_id=customer['id']
    else:
        customer_id=None
        name=request.form.get('name','').strip()
        phone=request.form.get('phone','').strip()
        address=request.form.get('address','').strip()

    if not name or not phone:
        c.close()
        flash('Name and phone number are required.','error')
        return redirect(url_for('home'))

    oid = c.execute('''INSERT INTO orders
        (product_id,customer_name,phone,address,qty,unit_price,fulfillment,payment_choice,created_at,customer_id)
        VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING id''',
        (p['id'],name,phone,address,qty,p['sell_price'],
         request.form.get('fulfillment','delivery'),
         request.form.get('payment_choice','pay_on_delivery'),now(),customer_id)
    ).fetchone()['id']

    c.commit()
    c.close()
    flash('Your order has been placed successfully! Reference #' + str(oid), 'success')
    return render_template('order_done.html',oid=oid)
@app.route('/setup',methods=['GET','POST'])
def setup():
    c=db(); exists=c.execute('SELECT COUNT(*) n FROM users').fetchone()['n']; c.close()
    if exists: return redirect(url_for('login'))
    if request.method=='POST':
        username=request.form.get('username','').strip(); password=request.form.get('password','')
        if len(username)<3 or len(password)<8: flash('Use a username of at least 3 characters and password of at least 8.','error')
        else:
            c=db(); c.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',(username,generate_password_hash(password),'admin',now())); c.commit(); c.close(); flash('Administrator created. Sign in.','success'); return redirect(url_for('login'))
    return render_template('setup.html')
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        c=db(); u=c.execute('SELECT * FROM users WHERE username=? AND active=1',(request.form.get('username','').strip(),)).fetchone(); c.close()
        if u and check_password_hash(u['password_hash'],request.form.get('password','')):
            session.clear(); session['uid']=u['id']; session.permanent = True; audit('login','Signed in'); return redirect(request.args.get('next') or url_for('dashboard'))
        flash('Incorrect username or password.','error')
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        code = request.form.get('recovery_code', '')
        new = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        configured_code = os.environ.get('LAVONNE_ADMIN_RECOVERY_CODE', '')

        if not configured_code:
            flash('Password recovery is not configured yet.', 'error')
        elif len(new) < 10 or new != confirm:
            flash('Passwords must match and contain at least 10 characters.', 'error')
        else:
            c = db()
            u = c.execute(
                "SELECT id FROM users WHERE username=? AND role='admin' AND active=1",
                (username,)
            ).fetchone()

            valid_code = hmac.compare_digest(code, configured_code)
            if u and valid_code:
                c.execute(
                    "UPDATE users SET password_hash=? WHERE id=? AND role='admin'",
                    (generate_password_hash(new), u['id'])
                )
                c.commit()
                c.close()
                flash('Administrator password reset. Please sign in.', 'success')
                return redirect(url_for('login'))

            c.close()
            flash('Recovery details are incorrect.', 'error')

    return render_template('forgot_password.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    selected=request.args.get('date',today())
    try: datetime.strptime(selected,'%Y-%m-%d')
    except: selected=today()
    c=db()
    sales=c.execute('SELECT COALESCE(SUM(total),0) gross,COALESCE(SUM(paid),0) collected,COALESCE(SUM(total-paid),0) credit,COALESCE(SUM(qty),0) units,COALESCE(SUM((unit_price-unit_cost)*qty),0) gross_profit FROM sales WHERE substr(sale_date,1,10)=?',(selected,)).fetchone()
    expenses=c.execute('SELECT COALESCE(SUM(amount),0) total FROM expenses WHERE expense_date=?',(selected,)).fetchone()['total']
    stock=c.execute('SELECT COALESCE(SUM(full_qty),0) fulls,COALESCE(SUM(empty_qty),0) empties FROM stock').fetchone()
    debt=c.execute('SELECT COALESCE(SUM(d.original-COALESCE(p.paid,0)),0) bal FROM debts d LEFT JOIN (SELECT debt_id,SUM(amount) paid FROM debt_payments GROUP BY debt_id) p ON p.debt_id=d.id').fetchone()['bal']
    recent=c.execute('SELECT s.paid,s.qty,s.total,p.brand,p.size FROM sales s JOIN products p ON p.id=s.product_id ORDER BY s.id DESC LIMIT 7').fetchall()
    orders=c.execute("SELECT COUNT(*) n FROM orders WHERE order_status IN ('new','awaiting_payment','authorised','out_for_delivery')").fetchone()['n']
    low_stock=c.execute('SELECT p.brand,p.size,s.full_qty FROM stock s JOIN products p ON p.id=s.product_id WHERE s.full_qty <= 5 AND p.active=1 ORDER BY s.full_qty').fetchall()
    c.close(); gp=money(sales['gross_profit']); return render_template('dashboard.html',selected=selected,sales=sales,expenses=expenses,net=gp-money(expenses),stock=stock,debt=debt,recent=recent,orders=orders,low_stock=low_stock)
@app.route('/products',methods=['GET','POST'])
@admin_required
def products_page():
    if request.method=='POST':
        brand=request.form.get('brand','').strip(); size=request.form.get('size','').strip()
        try: price=money(request.form.get('sell_price')); cost=money(request.form.get('buy_cost'))
        except: price=cost=0
        if not brand or size not in ('6kg','13kg'): flash('Enter a brand and valid cylinder size.','error')
        else:
            c=db(); c.execute('INSERT INTO products(brand,size,sell_price,buy_cost) VALUES(?,?,?,?) ON CONFLICT(brand,size) DO UPDATE SET sell_price=excluded.sell_price,buy_cost=excluded.buy_cost,active=1',(brand,size,price,cost)); pid=c.execute('SELECT id FROM products WHERE brand=? AND size=?',(brand,size)).fetchone()['id']; c.execute('INSERT INTO stock(product_id) VALUES(?) ON CONFLICT(product_id) DO NOTHING',(pid,)); c.commit(); c.close(); audit('product','Added/updated '+brand+' '+size); flash('Product saved.','success'); return redirect(url_for('products_page'))
    return render_template('products.html',products=get_products())
@app.route('/products/<int:pid>/image',methods=['POST'])
@admin_required
def product_image(pid):
    f=request.files.get('photo')
    if not f or not f.filename: flash('Choose an image first.','error'); return redirect(url_for('products_page'))
    ext=f.filename.rsplit('.',1)[-1].lower()
    if ext not in ALLOWED: flash('Use JPG, PNG or WEBP images.','error'); return redirect(url_for('products_page'))
    filename=f'product_{pid}_{secrets.token_hex(5)}.{ext}'; f.save(UPLOADS/filename)
    c=db(); c.execute('UPDATE products SET image=? WHERE id=?',(filename,pid)); c.commit(); c.close(); flash('Product photo updated.','success'); return redirect(url_for('products_page'))
@app.route('/inventory',methods=['GET','POST'])
@login_required
def inventory():
    if request.method=='POST':
        pid=int(request.form['product_id']); full=int(request.form.get('full_qty',0)); empty=int(request.form.get('empty_qty',0))
        c=db(); c.execute('UPDATE stock SET full_qty=GREATEST(0,full_qty+?),empty_qty=GREATEST(0,empty_qty+?) WHERE product_id=?',(full,empty,pid)); c.commit(); c.close(); audit('stock adjustment',f'Product {pid}: full {full}, empty {empty}'); flash('Stock adjusted.','success'); return redirect(url_for('inventory'))
    c=db()
    products=c.execute('SELECT p.id,p.brand,p.size,COALESCE(s.full_qty,0) full_qty,COALESCE(s.empty_qty,0) empty_qty FROM products p LEFT JOIN stock s ON s.product_id=p.id ORDER BY p.brand,p.size').fetchall()
    c.close()
    return render_template('inventory.html',products=products)
@app.route('/sales',methods=['GET','POST'])
@login_required
def sales():
    c=db()
    if request.method=='POST':
        pid=int(request.form['product_id']); qty=max(1,int(request.form['qty'])); price=money(request.form['unit_price']); paid=money(request.form['paid']); method=request.form.get('method','cash'); cid=request.form.get('customer_id') or None
        p=c.execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone(); st=c.execute('SELECT * FROM stock WHERE product_id=?',(pid,)).fetchone()
        if not p or not st or st['full_qty']<qty: flash('Not enough full cylinders in stock.','error')
        elif paid<0 or paid>price*qty: flash('Amount paid must be between zero and the sale total.','error')
        elif paid<price*qty and not cid: flash('Select a registered customer for a credit balance.','error')
        else:
            total=money(price*qty)
            sid=c.execute('INSERT INTO sales(product_id,customer_id,qty,unit_price,unit_cost,total,paid,payment_method,sale_date,user_id) VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING id',(pid,cid,qty,price,p['buy_cost'],total,paid,method,now(),session['uid'])).fetchone()['id']
            c.execute('UPDATE stock SET full_qty=full_qty-?,empty_qty=empty_qty+? WHERE product_id=?',(qty,qty,pid))
            if paid<total: c.execute('INSERT INTO debts(customer_id,sale_id,original,due_date,issued_at,created_by) VALUES(?,?,?,?,?,?)',(cid,sid,total-paid,request.form.get('due_date') or today(),now(),session['uid']))
            c.commit(); audit('sale',f'Sale #{sid}, total KSh {total}'); flash('Sale recorded and stock updated.','success'); c.close(); return redirect(url_for('sales'))
    products=c.execute('SELECT p.id,p.brand,p.size,COALESCE(st.full_qty,0) full_qty FROM products p LEFT JOIN stock st ON st.product_id=p.id ORDER BY p.brand,p.size').fetchall(); customers=c.execute('SELECT id,name,phone FROM customers ORDER BY name').fetchall(); rows=c.execute('SELECT s.sale_date,s.qty,s.total,s.paid,s.payment_method,p.brand,p.size,cu.name customer FROM sales s JOIN products p ON p.id=s.product_id LEFT JOIN customers cu ON cu.id=s.customer_id ORDER BY s.id DESC LIMIT 50').fetchall()
    # Weekday sales summary (current week)
    from datetime import timedelta as td
    today_d = date.today()
    start_of_week = (today_d - td(days=today_d.weekday())).isoformat()
    end_of_week = (today_d + td(days=6-today_d.weekday())).isoformat()
    week_rows = c.execute("""SELECT substr(sale_date,1,10) d, SUM(qty) units, SUM(total) amount, COUNT(*) txs
        FROM sales WHERE substr(sale_date,1,10) BETWEEN ? AND ? GROUP BY substr(sale_date,1,10)""", (start_of_week, end_of_week)).fetchall()
    week_map = {r['d']: r for r in week_rows}
    days = []
    for i in range(7):
        d = (today_d - td(days=today_d.weekday()) + td(days=i))
        key = d.isoformat()
        label = d.strftime('%A')
        info = week_map.get(key, {'units':0,'amount':0,'txs':0})
        days.append({'day': label, 'date': key, 'units': info['units'] or 0, 'amount': info['amount'] or 0, 'txs': info['txs'] or 0})
    week_total_units = sum(x['units'] for x in days)
    week_total_amount = sum(x['amount'] for x in days)
    # Month summary
    month_start = today_d.replace(day=1).isoformat()
    month_stats = c.execute("""SELECT COALESCE(SUM(qty),0) units, COALESCE(SUM(total),0) amount, COUNT(*) txs
        FROM sales WHERE substr(sale_date,1,10) >= ?""", (month_start,)).fetchone()
    c.close()
    return render_template('sales.html', products=products, customers=customers, rows=rows,
                           days=days, week_total_units=week_total_units, week_total_amount=week_total_amount,
                           month_units=month_stats['units'], month_amount=month_stats['amount'], month_txs=month_stats['txs'])
@app.route('/customers',methods=['GET','POST'])
@login_required
def customers():
    c=db()
    if request.method=='POST':
        c.execute('INSERT INTO customers(name,phone,address,created_at) VALUES(?,?,?,?)',(request.form['name'].strip(),request.form['phone'].strip(),request.form.get('address',''),now())); c.commit(); flash('Customer added.','success'); c.close(); return redirect(url_for('customers'))
    rows=c.execute('SELECT cu.id,cu.name,cu.phone,cu.address,COALESCE(SUM(d.original),0)-COALESCE((SELECT SUM(dp.amount) FROM debt_payments dp JOIN debts dx ON dx.id=dp.debt_id WHERE dx.customer_id=cu.id),0) balance FROM customers cu LEFT JOIN debts d ON d.customer_id=cu.id GROUP BY cu.id ORDER BY cu.name').fetchall(); c.close(); return render_template('customers.html',customers=rows)
@app.route('/debts')
@login_required
def debts():
    c=db(); rows=c.execute('SELECT d.id,d.original,d.due_date,d.issued_at,cu.name,cu.phone,COALESCE(SUM(dp.amount),0) paid FROM debts d JOIN customers cu ON cu.id=d.customer_id LEFT JOIN debt_payments dp ON dp.debt_id=d.id GROUP BY d.id ORDER BY d.due_date').fetchall(); payments=c.execute('SELECT dp.amount,dp.method,dp.paid_at,cu.name customer FROM debt_payments dp JOIN debts d ON d.id=dp.debt_id JOIN customers cu ON cu.id=d.customer_id ORDER BY dp.id DESC LIMIT 100').fetchall(); c.close(); items=[]
    for r in rows:
        x=dict(r); x['balance']=money(x['original']-x['paid']); x['status']='PAID' if x['balance']<=0 else ('OVERDUE' if x['due_date']<today() else ('DUE SOON' if x['due_date']<= (date.today()+timedelta(days=3)).isoformat() else 'OPEN')); items.append(x)
    return render_template('debts.html',debts=items,payments=payments)
@app.route('/debts/<int:did>/payment',methods=['POST'])
@login_required
def debt_payment(did):
    amount=money(request.form.get('amount')); c=db(); bal=balance(c,did)
    if amount<=0 or amount>bal: flash('Payment must be greater than zero and not exceed the balance.','error')
    else:
        c.execute('INSERT INTO debt_payments(debt_id,amount,method,paid_at,recorded_by,note) VALUES(?,?,?,?,?,?)',(did,amount,request.form.get('method','cash'),now(),session['uid'],request.form.get('note',''))); c.commit(); flash('Debt payment recorded.','success')
    c.close(); return redirect(url_for('debts'))
@app.route('/purchases',methods=['GET','POST'])
@admin_required
def purchases():
    c=db()
    if request.method=='POST':
        pid=int(request.form['product_id']); qty=max(1,int(request.form['qty'])); cost=money(request.form['unit_cost']); d=request.form.get('purchase_date') or today(); total=money(qty*cost)
        c.execute('INSERT INTO purchases(product_id,qty,unit_cost,total,purchase_date,supplier,user_id) VALUES(?,?,?,?,?,?,?)',(pid,qty,cost,total,d,request.form.get('supplier',''),session['uid'])); c.execute('UPDATE stock SET full_qty=full_qty+? WHERE product_id=?',(qty,pid)); c.execute('UPDATE products SET buy_cost=? WHERE id=?',(cost,pid)); c.commit(); c.close(); flash('Purchase saved and stock increased.','success'); return redirect(url_for('purchases'))
    prods=c.execute('SELECT id,brand,size FROM products ORDER BY brand,size').fetchall(); rows=c.execute('SELECT pu.purchase_date,pu.qty,pu.supplier,pu.total,pu.unit_cost,p.brand,p.size FROM purchases pu JOIN products p ON p.id=pu.product_id ORDER BY pu.id DESC LIMIT 30').fetchall(); c.close(); return render_template('purchases.html',products=prods,rows=rows)
@app.route('/expenses',methods=['GET','POST'])
@admin_required
def expenses():
    c=db()
    if request.method=='POST':
        c.execute('INSERT INTO expenses(title,amount,expense_date,note,user_id) VALUES(?,?,?,?,?)',(request.form['title'],money(request.form['amount']),request.form.get('expense_date') or today(),request.form.get('note',''),session['uid'])); c.commit(); c.close(); flash('Expense recorded.','success'); return redirect(url_for('expenses'))
    rows=c.execute('SELECT amount,expense_date,note,title FROM expenses ORDER BY id DESC LIMIT 40').fetchall(); c.close(); return render_template('expenses.html',rows=rows)
@app.route('/orders')
@login_required
def orders():
    c=db(); rows=c.execute('SELECT o.id,o.created_at,o.customer_name,o.phone,o.qty,o.fulfillment,o.unit_price,o.payment_choice,o.payment_status,o.order_status,o.delivery_note,p.brand,p.size FROM orders o JOIN products p ON p.id=o.product_id ORDER BY o.id DESC').fetchall(); c.close(); return render_template('orders.html',rows=rows)
@app.route('/orders/<int:oid>/update',methods=['POST'])
@login_required
def update_order(oid):
    c=db(); o=c.execute('SELECT * FROM orders WHERE id=?',(oid,)).fetchone()
    if not o: c.close(); abort(404)
    if o['order_status']=='delivered':
        c.close(); flash('This order is already completed. Contact the administrator if a correction is needed.','error'); return redirect(url_for('orders'))
    pay=request.form.get('payment_status',o['payment_status']); status=request.form.get('order_status',o['order_status'])
    allowed_pay={'unverified','verified','pledged'}; allowed_status={'new','awaiting_payment','authorised','out_for_delivery','delivered','failed','customer_unavailable','returned'}
    if pay not in allowed_pay or status not in allowed_status: c.close(); abort(400)
    if status in ('authorised','out_for_delivery','delivered') and pay not in ('verified','pledged'): flash('Verify payment or record an approved pledge before dispatch.','error')
    elif status=='delivered' and o['order_status']!='delivered':
        st=c.execute('SELECT full_qty FROM stock WHERE product_id=?',(o['product_id'],)).fetchone()
        if not st or st['full_qty']<o['qty']: flash('Insufficient stock to complete delivery.','error')
        else:
            c.execute('UPDATE stock SET full_qty=full_qty-?,empty_qty=empty_qty+? WHERE product_id=?',(o['qty'],o['qty'],o['product_id']))
            customer=c.execute('SELECT id FROM customers WHERE phone=?',(o['phone'],)).fetchone()
            if not customer:
                cid=c.execute('INSERT INTO customers(name,phone,address,created_at) VALUES(?,?,?,?) RETURNING id',(o['customer_name'],o['phone'],o['address'],now())).fetchone()['id']
            else: cid=customer['id']
            paid=money(o['unit_price']*o['qty']) if pay=='verified' else 0
            prod=c.execute('SELECT buy_cost FROM products WHERE id=?',(o['product_id'],)).fetchone()
            sid=c.execute('INSERT INTO sales(product_id,customer_id,qty,unit_price,unit_cost,total,paid,payment_method,sale_date,user_id,note) VALUES(?,?,?,?,?,?,?,?,?,?,?) RETURNING id',(o['product_id'],cid,o['qty'],o['unit_price'],prod['buy_cost'],money(o['unit_price']*o['qty']),paid,'order',now(),session['uid'],'Customer order #'+str(oid))).fetchone()['id']
            if pay=='pledged': c.execute('INSERT INTO debts(customer_id,sale_id,original,due_date,issued_at,created_by,note) VALUES(?,?,?,?,?,?,?)',(cid,sid,money(o['unit_price']*o['qty']),today(),now(),session['uid'],'Order pledge #'+str(oid)))
            c.execute('UPDATE orders SET payment_status=?,order_status=?,handled_by=?,delivered_by=?,delivery_note=? WHERE id=?',(pay,status,session['uid'],session['uid'],request.form.get('delivery_note',''),oid)); c.commit(); c.close(); flash('Delivery completed; sale and stock have been updated.','success'); return redirect(url_for('orders'))
    else:
        c.execute('UPDATE orders SET payment_status=?,order_status=?,handled_by=?,delivery_note=? WHERE id=?',(pay,status,session['uid'],request.form.get('delivery_note',''),oid)); c.commit(); flash('Order updated.','success')
    c.close(); return redirect(url_for('orders'))
@app.route('/reports')
@admin_required
def reports():
    start = request.args.get('start', today())
    end = request.args.get('end', today())
    c = db()

    daily = c.execute("""
        SELECT SUBSTR(CAST(s.sale_date AS TEXT),1,10) AS report_date,
               COALESCE(SUM(s.total),0) AS sales,
               COALESCE(SUM(s.paid),0) AS collected,
               COALESCE(SUM((s.unit_price-s.unit_cost)*s.qty),0) AS gross_profit,
               COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '6%' THEN s.qty ELSE 0 END),0) AS six_kg_sold,
               COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '13%' THEN s.qty ELSE 0 END),0) AS thirteen_kg_sold
        FROM sales s JOIN products p ON p.id=s.product_id
        WHERE SUBSTR(CAST(s.sale_date AS TEXT),1,10) BETWEEN ? AND ?
        GROUP BY SUBSTR(CAST(s.sale_date AS TEXT),1,10)
        ORDER BY report_date DESC
    """,(start,end)).fetchall()

    expenses = c.execute("""
        SELECT expense_date, COALESCE(SUM(amount),0) AS amount
        FROM expenses
        WHERE expense_date BETWEEN ? AND ?
        GROUP BY expense_date
    """,(start,end)).fetchall()

    exp={str(x['expense_date']):float(x['amount'] or 0) for x in expenses}
    daily_rows=[]

    for r in daily:
        d=str(r['report_date'])
        gross=float(r['gross_profit'] or 0)
        e=exp.get(d,0)
        daily_rows.append({
            'date':d,
            'day':__import__('datetime').date.fromisoformat(d).strftime('%A'),
            'sales':float(r['sales'] or 0),
            'collected':float(r['collected'] or 0),
            'gross_profit':gross,
            'expenses':e,
            'net_profit':gross-e,
            'six_kg_sold':int(r['six_kg_sold'] or 0),
            'thirteen_kg_sold':int(r['thirteen_kg_sold'] or 0)
        })

    rows=c.execute("""
        SELECT p.brand,p.size,
               COALESCE(SUM(s.qty),0) AS qty,
               COALESCE(SUM(s.total),0) AS sales,
               COALESCE(SUM((s.unit_price-s.unit_cost)*s.qty),0) AS profit
        FROM sales s JOIN products p ON p.id=s.product_id
        WHERE SUBSTR(CAST(s.sale_date AS TEXT),1,10) BETWEEN ? AND ?
        GROUP BY p.id,p.brand,p.size
        ORDER BY sales DESC
    """,(start,end)).fetchall()

    stock=c.execute("""
        SELECT
        COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '6%' THEN s.full_qty ELSE 0 END),0) AS six_full,
        COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '6%' THEN s.empty_qty ELSE 0 END),0) AS six_empty,
        COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '13%' THEN s.full_qty ELSE 0 END),0) AS thirteen_full,
        COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '13%' THEN s.empty_qty ELSE 0 END),0) AS thirteen_empty
        FROM stock s JOIN products p ON p.id=s.product_id
    """).fetchone()

    c.close()

    total=sum(x['sales'] for x in daily_rows)
    collected=sum(x['collected'] for x in daily_rows)
    gp=sum(x['gross_profit'] for x in daily_rows)
    exp_total=sum(x['expenses'] for x in daily_rows)

    return render_template(
        'reports.html',
        start=start,end=end,daily=daily_rows,rows=rows,
        total=total,collected=collected,gp=gp,
        expenses=exp_total,net=gp-exp_total,
        total_6kg=sum(x['six_kg_sold'] for x in daily_rows),
        total_13kg=sum(x['thirteen_kg_sold'] for x in daily_rows),
        stock=stock
    )

@app.route('/reports.csv')
@admin_required
def reports_csv():
    import csv
    from io import StringIO

    start=request.args.get('start',today())
    end=request.args.get('end',today())
    c=db()

    rows=c.execute("""
        SELECT SUBSTR(CAST(s.sale_date AS TEXT),1,10) AS report_date,
               COALESCE(SUM(s.total),0) AS sales,
               COALESCE(SUM(s.paid),0) AS collected,
               COALESCE(SUM((s.unit_price-s.unit_cost)*s.qty),0) AS gross_profit,
               COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '6%' THEN s.qty ELSE 0 END),0) AS six_kg_sold,
               COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '13%' THEN s.qty ELSE 0 END),0) AS thirteen_kg_sold
        FROM sales s JOIN products p ON p.id=s.product_id
        WHERE SUBSTR(CAST(s.sale_date AS TEXT),1,10) BETWEEN ? AND ?
        GROUP BY SUBSTR(CAST(s.sale_date AS TEXT),1,10)
        ORDER BY report_date DESC
    """,(start,end)).fetchall()

    expenses=c.execute("""
        SELECT expense_date,COALESCE(SUM(amount),0) AS amount
        FROM expenses
        WHERE expense_date BETWEEN ? AND ?
        GROUP BY expense_date
    """,(start,end)).fetchall()

    exp={str(x['expense_date']):float(x['amount'] or 0) for x in expenses}

    stock=c.execute("""
        SELECT
        COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '6%' THEN s.full_qty ELSE 0 END),0) AS six_full,
        COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '6%' THEN s.empty_qty ELSE 0 END),0) AS six_empty,
        COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '13%' THEN s.full_qty ELSE 0 END),0) AS thirteen_full,
        COALESCE(SUM(CASE WHEN LOWER(p.size) LIKE '13%' THEN s.empty_qty ELSE 0 END),0) AS thirteen_empty
        FROM stock s JOIN products p ON p.id=s.product_id
    """).fetchone()

    out=StringIO()
    w=csv.writer(out)
    w.writerow(['Date','Day','6kg Sold','13kg Sold','Sales','Collected',
                'Gross Profit','Expenses','Net Profit','6kg Full','6kg Empty',
                '13kg Full','13kg Empty'])

    for r in rows:
        d=str(r['report_date'])
        gross=float(r['gross_profit'] or 0)
        e=exp.get(d,0)
        w.writerow([
            d,__import__('datetime').date.fromisoformat(d).strftime('%A'),
            int(r['six_kg_sold'] or 0),int(r['thirteen_kg_sold'] or 0),
            round(float(r['sales'] or 0),2),round(float(r['collected'] or 0),2),
            round(gross,2),round(e,2),round(gross-e,2),
            stock['six_full'],stock['six_empty'],
            stock['thirteen_full'],stock['thirteen_empty']
        ])

    c.close()
    return Response(
        out.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition':
                 f'attachment; filename=lavonne_daily_report_{start}_to_{end}.csv'}
    )
@app.route('/team',methods=['GET','POST'])
@admin_required
def team():
    c=db()
    if request.method=='POST':
        username=request.form['username'].strip(); password=request.form['password']
        if len(password)<8: flash('Password must be at least 8 characters.','error')
        else:
            try: c.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',(username,generate_password_hash(password),'employee',now())); c.commit(); flash('Employee account created.','success')
            except DB_INTEGRITY_ERROR:
                c.rollback()
                flash('That username already exists.','error')
    rows=c.execute('SELECT id,username,role,active,created_at FROM users ORDER BY id').fetchall(); c.close(); return render_template('team.html',users=rows)
@app.route('/team/<int:uid>/toggle',methods=['POST'])
@admin_required
def toggle_user(uid):
    if uid==session['uid']: flash('You cannot disable your own account.','error')
    else:
        c=db(); c.execute('UPDATE users SET active=1-active WHERE id=?',(uid,)); c.commit(); c.close(); flash('Account status changed.','success')
    return redirect(url_for('team'))
@app.route('/account/password',methods=['POST'])
@login_required
def password_change():
    old=request.form.get('old',''); new=request.form.get('new',''); c=db(); u=c.execute('SELECT * FROM users WHERE id=?',(session['uid'],)).fetchone()
    if not check_password_hash(u['password_hash'],old) or len(new)<8: flash('Current password is incorrect or new password is too short.','error')
    else: c.execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(new),session['uid'])); c.commit(); flash('Password changed.','success')
    c.close(); return redirect(url_for('dashboard'))

@app.route('/news', methods=['GET','POST'])
@admin_required
def news_admin():
    c = db()
    if request.method == 'POST':
        title = request.form.get('title','').strip()
        body = request.form.get('body','').strip()
        tag = request.form.get('tag','Info')
        important = 1 if request.form.get('important') else 0
        image_name = None
        f = request.files.get('image')
        if f and f.filename:
            ext = f.filename.rsplit('.',1)[-1].lower()
            if ext in ALLOWED:
                image_name = secure_filename(f'{secrets.token_hex(8)}.{ext}')
                f.save(str(UPLOADS / image_name))
        if title and body:
            c.execute('INSERT INTO news(title,body,image,tag,important,created_at,created_by) VALUES(?,?,?,?,?,?,?)',
                      (title, body, image_name, tag, important, now(), session['uid']))
            c.commit()
            flash('Announcement published.','success')
        else:
            flash('Title and body are required.','error')
        c.close()
        return redirect(url_for('news_admin'))
    rows = c.execute('SELECT * FROM news ORDER BY id DESC LIMIT 30').fetchall()
    c.close()
    return render_template('news_admin.html', rows=rows)

@app.route('/news/<int:nid>/toggle', methods=['POST'])
@admin_required
def news_toggle(nid):
    c = db()
    c.execute('UPDATE news SET active = 1 - active WHERE id=?', (nid,))
    c.commit(); c.close()
    flash('Announcement status updated.','success')
    return redirect(url_for('news_admin'))

@app.route('/stock/confirm', methods=['GET','POST'])
@login_required
def stock_confirm():
    c = db()
    products = c.execute('SELECT p.id,p.brand,p.size,COALESCE(s.full_qty,0) full_qty,COALESCE(s.empty_qty,0) empty_qty FROM products p LEFT JOIN stock s ON s.product_id=p.id ORDER BY p.brand,p.size').fetchall()
    if request.method == 'POST':
        confirm_date = request.form.get('confirm_date') or today()
        for p in products:
            full = int(request.form.get(f'full_{p["id"]}', p['full_qty']))
            empty = int(request.form.get(f'empty_{p["id"]}', p['empty_qty']))
            c.execute('INSERT INTO stock_confirmations(confirm_date,product_id,full_qty,empty_qty,confirmed_by,created_at) VALUES(?,?,?,?,?,?)',
                      (confirm_date, p['id'], full, empty, session['uid'], now()))
            c.execute('UPDATE stock SET full_qty=?, empty_qty=? WHERE product_id=?', (full, empty, p['id']))
        c.commit(); c.close()
        audit('stock_confirm', f'Daily stock confirmed for {confirm_date}')
        flash('Daily stock confirmation saved.','success')
        return redirect(url_for('stock_confirm'))
    today_conf = c.execute('SELECT * FROM stock_confirmations WHERE confirm_date=? ORDER BY id DESC', (today(),)).fetchall()
    c.close()
    return render_template('stock_confirm.html', products=products, today_conf=today_conf)

@app.route('/deposits', methods=['GET','POST'])
@login_required
def deposits():
    c = db()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            cid = int(request.form['customer_id'])
            pid = request.form.get('product_id') or None
            qty = max(1, int(request.form.get('qty',1)))
            amount = money(request.form.get('deposit_amount',0))
            note = request.form.get('note','')
            c.execute('INSERT INTO cylinder_deposits(customer_id,product_id,qty,deposit_amount,status,issued_at,note,created_by) VALUES(?,?,?,?,?,?,?,?)',
                      (cid, pid, qty, amount, 'outstanding', now(), note, session['uid']))
            c.commit()
            flash('Cylinder deposit recorded.','success')
        elif action == 'return':
            did = int(request.form['deposit_id'])
            c.execute("UPDATE cylinder_deposits SET status='returned', returned_at=? WHERE id=?", (now(), did))
            c.commit()
            flash('Cylinder marked as returned.','success')
        c.close()
        return redirect(url_for('deposits'))
    rows = c.execute('SELECT d.id,d.deposit_amount,d.issued_at,d.qty,d.status,cu.name,cu.phone,p.brand,p.size FROM cylinder_deposits d JOIN customers cu ON cu.id=d.customer_id LEFT JOIN products p ON p.id=d.product_id ORDER BY d.id DESC LIMIT 50').fetchall()
    customers = c.execute('SELECT id,name,phone FROM customers ORDER BY name').fetchall()
    products = c.execute('SELECT id,brand,size FROM products ORDER BY brand,size').fetchall()
    outstanding = c.execute("SELECT COUNT(*) n FROM cylinder_deposits WHERE status='outstanding'").fetchone()['n']
    c.close()
    return render_template('deposits.html', rows=rows, customers=customers, products=products, outstanding=outstanding)


@app.errorhandler(403)

def forbidden(e):
    return render_template(
        'message.html',
        heading='Access restricted',
        message='This section is available to the administrator only.'
    ), 403

@app.route('/robots.txt')
def robots_txt():
    return Response(
        "User-agent: *\n"
        "Allow: /\n"
        "Sitemap: https://lavonne-gas-new.onrender.com/sitemap.xml\n",
        mimetype='text/plain'
    )

@app.route('/sitemap.xml')
def sitemap_xml():
    urls = [
        url_for('inventory', _external=True),
        url_for('login', _external=True),
        url_for('customer_login', _external=True),
        url_for('customer_register', _external=True),
    ]

    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'

    for u in urls:
        xml += f'  <url><loc>{u}</loc></url>\n'

    xml += '</urlset>'
    return Response(xml, mimetype='application/xml')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
