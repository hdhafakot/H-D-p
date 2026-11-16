import os,sqlite3,secrets,hashlib,hmac,time,io,csv
from cryptography.fernet import Fernet, InvalidToken
from collections import defaultdict, deque
from pathlib import Path
from contextlib import contextmanager
from fastapi import FastAPI,Request,HTTPException
from fastapi.responses import FileResponse,StreamingResponse,Response
from pydantic import BaseModel
import qrcode
ROOT=Path(__file__).parent
DB=Path(os.environ.get('HD_DB',str(ROOT/'hd.sqlite3')))
app=FastAPI(title='H&D Productions Staff')
# Key must remain stable across restarts and backups. Do not store it with the database.
def cipher():
 key=os.environ.get('HD_DATA_KEY','')
 if not key: raise RuntimeError('HD_DATA_KEY is required; generate with Fernet.generate_key()')
 return Fernet(key.encode())
def seal_bytes(v):
 return b'enc:'+cipher().encrypt(v) if v else b''
def seal(v):
 return 'enc:'+cipher().encrypt(v.encode()).decode() if v else ''
def unseal(v):
 if not v:return b''
 if isinstance(v,str) and v.startswith('enc:'):return cipher().decrypt(v[4:].encode())
 if isinstance(v,bytes) and v.startswith(b'enc:'):return cipher().decrypt(v[4:])
 raise RuntimeError('Unencrypted legacy sensitive data found: migration required before serving')
_attempts=defaultdict(deque)
@app.middleware('http')
async def security_headers(request,call_next):
 if request.method not in ('GET','HEAD','OPTIONS') and request.url.path.startswith('/api/'):
  origin=request.headers.get('origin')
  host=request.headers.get('host','')
  if origin:
   from urllib.parse import urlparse
   parsed=urlparse(origin)
   if parsed.netloc!=host or parsed.scheme!=request.url.scheme:
    return Response('Origin rejected',status_code=403)
  elif request.headers.get('sec-fetch-site') not in (None,'same-origin','none'):
   return Response('Cross-site request rejected',status_code=403)
 response=await call_next(request)
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['Referrer-Policy']='no-referrer'
 response.headers['X-Frame-Options']='DENY'
 response.headers['Cache-Control']='no-store'
 response.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
 return response
@app.on_event('startup')
def validate_encryption():
 cipher()
 with db() as c:
  if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='admissions'").fetchone():
   cols={x['name'] for x in c.execute('PRAGMA table_info(admissions)')}
   if 'identity_number' in cols:
    for a in c.execute('SELECT identity_number,guardian_identity_number,guardian_document FROM admissions'):
     for name in ('identity_number','guardian_identity_number','guardian_document'):
      value=a[name]
      if value and not (value.startswith('enc:') if isinstance(value,str) else value.startswith(b'enc:')):
       raise RuntimeError('Existing plaintext identity/document data: migrate offline before starting')

@contextmanager
def db():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON')
 try: yield c;c.commit()
 finally:c.close()
def hashpw(p,s=None):
 s=s or secrets.token_hex(16)
 return s+':'+hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),260000).hex()
def verify(p,v):
 try:s,h=v.split(':');return hmac.compare_digest(hashpw(p,s),v)
 except:return False
@app.on_event('startup')
def init():
 with db() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,phone TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','staff')),active INTEGER DEFAULT 1);
  CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires INTEGER NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
  CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,title TEXT NOT NULL,venue TEXT,date TEXT,capacity INTEGER DEFAULT 0);
  CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,event_id INTEGER NOT NULL,owner_id INTEGER NOT NULL,customer TEXT NOT NULL,phone TEXT,guests INTEGER DEFAULT 1,room TEXT,amount REAL DEFAULT 0,status TEXT DEFAULT 'pending',created INTEGER NOT NULL,FOREIGN KEY(event_id) REFERENCES events(id),FOREIGN KEY(owner_id) REFERENCES users(id));
  CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL,amount REAL NOT NULL,method TEXT NOT NULL,note TEXT,created INTEGER NOT NULL,FOREIGN KEY(order_id) REFERENCES orders(id));
  CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL,token TEXT UNIQUE NOT NULL,used_at INTEGER,FOREIGN KEY(order_id) REFERENCES orders(id));''')
  if not c.execute('SELECT 1 FROM users').fetchone():
   pw=os.environ.get('HD_ADMIN_PASSWORD');phone=os.environ.get('HD_ADMIN_PHONE')
   if not pw or not phone: raise RuntimeError('Set HD_ADMIN_PHONE and HD_ADMIN_PASSWORD environment variables before starting')
   c.execute('INSERT INTO users(name,phone,password,role) VALUES(?,?,?,?)',('מנהלת',phone,hashpw(pw),'admin'))
def auth(r):
 token=r.cookies.get('hd_session','');th=hashlib.sha256(token.encode()).hexdigest()
 with db() as c:
  u=c.execute('SELECT u.id,u.name,u.role,u.active FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token_hash=? AND s.expires>?',(th,int(time.time()))).fetchone()
 if not u or not u['active']:raise HTTPException(401,'יש להתחבר')
 return dict(u)
def admin(u):
 if u['role']!='admin':raise HTTPException(403,'אין הרשאה')
def order_access(c,u,oid):
 o=c.execute('SELECT * FROM orders WHERE id=?',(oid,)).fetchone()
 if not o or (u['role']!='admin' and o['owner_id']!=u['id']):raise HTTPException(404,'הזמנה לא נמצאה')
 return o
class Login(BaseModel):phone:str;password:str
@app.post('/api/login')
def login(data:Login,r:Request):
 ip=r.client.host if r.client else 'unknown'
 key=(ip,data.phone); now=time.time(); q=_attempts[key]
 while q and q[0]<now-900:q.popleft()
 if len(q)>=8:raise HTTPException(429,'יותר מדי ניסיונות התחברות, נסו מאוחר יותר')
 q.append(now)
 with db() as c:
  u=c.execute('SELECT * FROM users WHERE phone=? AND active=1',(data.phone,)).fetchone()
  if not u or not verify(data.password,u['password']):raise HTTPException(401,'פרטי התחברות שגויים')
  q.clear()
  token=secrets.token_urlsafe(40)
  c.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],int(time.time())+28800))
 from fastapi.responses import JSONResponse
 response=JSONResponse({'ok':True});response.set_cookie('hd_session',token,httponly=True,secure=os.environ.get('HD_DEV_HTTP')!='1',samesite='strict',max_age=28800,path='/');return response
@app.post('/api/logout')
def logout(r:Request):
 with db() as c:c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(r.cookies.get('hd_session','').encode()).hexdigest(),))
 from fastapi.responses import JSONResponse
 x=JSONResponse({'ok':True});x.delete_cookie('hd_session');return x
@app.get('/api/me')
def me(r:Request):return auth(r)
@app.get('/api/events')
def events(r:Request):
 auth(r)
 with db() as c:return [dict(x) for x in c.execute('SELECT * FROM events ORDER BY date DESC,id DESC')]
class Event(BaseModel):title:str;venue:str='';date:str='';capacity:int=0
@app.post('/api/events')
def create_event(v:Event,r:Request):
 admin(auth(r))
 with db() as c:
  cur=c.execute('INSERT INTO events(title,venue,date,capacity) VALUES(?,?,?,?)',(v.title,v.venue,v.date,v.capacity));return {'id':cur.lastrowid}
@app.get('/api/users')
def users(r:Request):
 admin(auth(r))
 with db() as c:return [dict(x) for x in c.execute('SELECT id,name,phone,role,active FROM users ORDER BY id')]
class User(BaseModel):name:str;phone:str;password:str;role:str='staff'
@app.post('/api/users')
def add_user(v:User,r:Request):
 admin(auth(r))
 if v.role not in ('admin','staff') or len(v.password)<10:raise HTTPException(400,'סיסמה חייבת להכיל לפחות 10 תווים')
 with db() as c:
  try:cur=c.execute('INSERT INTO users(name,phone,password,role) VALUES(?,?,?,?)',(v.name,v.phone,hashpw(v.password),v.role));return {'id':cur.lastrowid}
  except sqlite3.IntegrityError:raise HTTPException(400,'מספר הטלפון כבר קיים')
@app.post('/api/users/{uid}/disable')
def disable(uid:int,r:Request):
 u=auth(r);admin(u)
 if uid==u['id']:raise HTTPException(400,'לא ניתן להשבית את עצמך')
 with db() as c:c.execute('UPDATE users SET active=0 WHERE id=?',(uid,));c.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
 return {'ok':True}
@app.get('/api/orders')
def orders(r:Request):
 u=auth(r)
 with db() as c:
  sql='''SELECT o.*,e.title AS event_title,us.name AS owner_name,COALESCE((SELECT SUM(amount) FROM payments WHERE order_id=o.id),0) paid FROM orders o JOIN events e ON e.id=o.event_id JOIN users us ON us.id=o.owner_id'''
  if u['role']=='admin':rows=c.execute(sql+' ORDER BY o.id DESC')
  else:rows=c.execute(sql+' WHERE o.owner_id=? ORDER BY o.id DESC',(u['id'],))
  return [dict(x) for x in rows]
class Order(BaseModel):event_id:int;customer:str;phone:str='';guests:int=1;room:str='';amount:float=0;owner_id:int|None=None
@app.post('/api/orders')
def create_order(v:Order,r:Request):
 u=auth(r)
 if v.guests<1 or v.amount<0:raise HTTPException(400,'נתוני הזמנה לא תקינים')
 owner=v.owner_id if u['role']=='admin' and v.owner_id else u['id']
 with db() as c:
  if not c.execute('SELECT 1 FROM events WHERE id=?',(v.event_id,)).fetchone():raise HTTPException(400,'אירוע לא נמצא')
  if not c.execute('SELECT 1 FROM users WHERE id=? AND active=1',(owner,)).fetchone():raise HTTPException(400,'עובד לא נמצא')
  cur=c.execute('INSERT INTO orders(event_id,owner_id,customer,phone,guests,room,amount,created) VALUES(?,?,?,?,?,?,?,?)',(v.event_id,owner,v.customer,v.phone,v.guests,v.room,v.amount,int(time.time())))
  return {'id':cur.lastrowid}
class Status(BaseModel):status:str
@app.post('/api/orders/{oid}/status')
def status(oid:int,v:Status,r:Request):
 u=auth(r)
 if v.status not in ('pending','confirmed','cancelled'):raise HTTPException(400,'סטטוס לא תקין')
 with db() as c:order_access(c,u,oid);c.execute('UPDATE orders SET status=? WHERE id=?',(v.status,oid))
 return {'ok':True}
class Payment(BaseModel):amount:float;method:str;note:str=''
@app.post('/api/orders/{oid}/payments')
def payment(oid:int,v:Payment,r:Request):
 u=auth(r)
 if v.amount<=0 or v.method not in ('bank','bit','cash','other'):raise HTTPException(400,'תשלום לא תקין')
 with db() as c:
  o=order_access(c,u,oid)
  paid=c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE order_id=?',(oid,)).fetchone()[0]
  if paid+v.amount>o['amount']+0.001:raise HTTPException(400,'הסכום גבוה מהיתרה')
  c.execute('INSERT INTO payments(order_id,amount,method,note,created) VALUES(?,?,?,?,?)',(oid,v.amount,v.method,v.note,int(time.time())))
 return {'ok':True}
@app.get('/api/orders/{oid}/voucher')
def voucher(oid:int,r:Request):
 u=auth(r)
 with db() as c:
  o=order_access(c,u,oid)
  e=c.execute('SELECT * FROM events WHERE id=?',(o['event_id'],)).fetchone()
  paid=c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE order_id=?',(oid,)).fetchone()[0]
  return {'order':dict(o),'event':dict(e),'paid':paid}
@app.post('/api/orders/{oid}/tickets')
def tickets(oid:int,r:Request):
 u=auth(r)
 with db() as c:
  o=order_access(c,u,oid)
  if o['status']!='confirmed':raise HTTPException(400,'יש לאשר את ההזמנה קודם')
  existing=c.execute('SELECT COUNT(*) FROM tickets WHERE order_id=?',(oid,)).fetchone()[0]
  for _ in range(max(0,o['guests']-existing)):c.execute('INSERT INTO tickets(order_id,token) VALUES(?,?)',(oid,secrets.token_urlsafe(24)))
  return [{'id':x['id'],'token':x['token'],'used_at':x['used_at']} for x in c.execute('SELECT * FROM tickets WHERE order_id=?',(oid,))]
@app.get('/api/tickets/{token}/qr')
def qr(token:str,r:Request):
 u=auth(r)
 with db() as c:
  t=c.execute('SELECT * FROM tickets WHERE token=?',(token,)).fetchone()
  if not t:raise HTTPException(404)
  order_access(c,u,t['order_id'])
 img=qrcode.make(token);out=io.BytesIO();img.save(out,format='PNG');out.seek(0)
 return StreamingResponse(out,media_type='image/png')
class Scan(BaseModel):token:str
@app.post('/api/scan')
def scan(v:Scan,r:Request):
 u=auth(r)
 with db() as c:
  t=c.execute('SELECT t.*,o.customer,o.owner_id,o.status FROM tickets t JOIN orders o ON o.id=t.order_id WHERE t.token=?',(v.token,)).fetchone()
  if not t or (u['role']!='admin' and t['owner_id']!=u['id']):raise HTTPException(404,'כרטיס לא נמצא או אין הרשאה')
  if t['used_at']:raise HTTPException(409,'הכרטיס כבר נסרק')
  if t['status']!='confirmed':raise HTTPException(400,'ההזמנה אינה מאושרת')
  c.execute('UPDATE tickets SET used_at=? WHERE id=? AND used_at IS NULL',(int(time.time()),t['id']))
  return {'ok':True,'customer':t['customer']}
@app.get('/')
def home():return FileResponse(ROOT/'static'/'index.html')

# Event admission extension: per-guest admission passes and parental documents.
from fastapi import UploadFile, File, Form
from fastapi.responses import Response
from html import escape
import json
@app.on_event('startup')
def init_admissions():
 with db() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS admissions(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL,guest_name TEXT NOT NULL,age INTEGER, eilat_resident INTEGER NOT NULL DEFAULT 0, zone TEXT NOT NULL CHECK(zone IN ('A','B','C','VIP')),entry_type TEXT NOT NULL CHECK(entry_type IN ('26','26-27')),event_time TEXT,seat TEXT,table_name TEXT,notes TEXT,guardian_name TEXT,guardian_consent INTEGER NOT NULL DEFAULT 0,guardian_signature TEXT,guardian_document_name TEXT,guardian_document BLOB,guardian_document_type TEXT,created INTEGER NOT NULL,FOREIGN KEY(order_id) REFERENCES orders(id));
  CREATE UNIQUE INDEX IF NOT EXISTS admissions_order_guest ON admissions(order_id,guest_name);''')
def valid_israeli_id(value:str)->bool:
 value=value.strip()
 if len(value)!=9 or not value.isascii() or not value.isdigit():return False
 return sum((lambda x:x if x<10 else x-9)(int(ch)*(1 if i%2==0 else 2)) for i,ch in enumerate(value))%10==0

@app.on_event('startup')
def migrate_identity_fields():
 with db() as c:
  cols={x['name'] for x in c.execute('PRAGMA table_info(admissions)')}
  for col in ('identity_number','guardian_identity_number'):
   if col not in cols:c.execute(f'ALTER TABLE admissions ADD COLUMN {col} TEXT')

class Admission(BaseModel):
 order_id:int;guest_name:str;identity_number:str;guardian_identity_number:str='';age:int|None=None;eilat_resident:bool=False;zone:str='C';entry_type:str='26';event_time:str='';seat:str='';table_name:str='';notes:str='';guardian_name:str='';guardian_consent:bool=False;guardian_signature:str=''
@app.post('/api/admissions')
def create_admission(v:Admission,r:Request):
 u=auth(r)
 if not v.guest_name.strip() or v.zone not in ('A','B','C','VIP') or v.entry_type not in ('26','26-27'):raise HTTPException(400,'פרטי כרטיס לא תקינים')
 if not valid_israeli_id(v.identity_number):raise HTTPException(400,'מספר תעודת זהות של האורח אינו תקין')
 if v.age is not None and v.age<18 and not valid_israeli_id(v.guardian_identity_number):raise HTTPException(400,'יש להזין תעודת זהות תקינה של הורה')
 if v.guardian_identity_number and not valid_israeli_id(v.guardian_identity_number):raise HTTPException(400,'תעודת זהות של הורה אינה תקינה')
 if v.age is not None and (v.age<0 or v.age>120):raise HTTPException(400,'גיל לא תקין')
 if v.zone=='VIP' and not v.table_name.strip():raise HTTPException(400,'יש לציין שולחן VIP')
 if v.age is not None and v.age<18 and (not v.guardian_consent or not v.guardian_name.strip() or not v.guardian_signature.strip()):raise HTTPException(400,'נדרשת הסכמת הורה וחתימה לקטין')
 with db() as c:
  o=order_access(c,u,v.order_id)
  count=c.execute('SELECT COUNT(*) FROM admissions WHERE order_id=?',(v.order_id,)).fetchone()[0]
  if count>=o['guests']:raise HTTPException(400,'מספר האורחים בהזמנה הושלם')
  try:
   cur=c.execute('''INSERT INTO admissions(order_id,guest_name,age,eilat_resident,zone,entry_type,event_time,seat,table_name,notes,guardian_name,guardian_consent,guardian_signature,identity_number,guardian_identity_number,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(v.order_id,v.guest_name.strip(),v.age,int(v.eilat_resident),v.zone,v.entry_type,v.event_time,v.seat,v.table_name,v.notes,v.guardian_name,int(v.guardian_consent),v.guardian_signature,seal(v.identity_number.strip()),seal(v.guardian_identity_number.strip()),int(time.time())))
  except sqlite3.IntegrityError:raise HTTPException(400,'שם האורח כבר קיים בהזמנה')
  return {'id':cur.lastrowid,'requires_document':v.age is not None and v.age<18}
@app.get('/api/orders/{oid}/admissions')
def list_admissions(oid:int,r:Request):
 u=auth(r)
 with db() as c:
  order_access(c,u,oid)
  return [dict(x) for x in c.execute('''SELECT id,order_id,guest_name,CASE WHEN identity_number IS NOT NULL AND identity_number!='' THEN 1 ELSE 0 END AS identity_recorded,CASE WHEN guardian_identity_number IS NOT NULL AND guardian_identity_number!='' THEN 1 ELSE 0 END AS guardian_identity_recorded,age,eilat_resident,zone,entry_type,event_time,seat,table_name,notes,guardian_name,guardian_consent,CASE WHEN guardian_document IS NULL THEN 0 ELSE 1 END AS document_uploaded FROM admissions WHERE order_id=? ORDER BY id''',(oid,))]
@app.post('/api/admissions/{aid}/document')
async def admission_document(aid:int,r:Request,document:UploadFile=File(...)):
 u=auth(r)
 with db() as c:
  a=c.execute('SELECT * FROM admissions WHERE id=?',(aid,)).fetchone()
  if not a:raise HTTPException(404)
  order_access(c,u,a['order_id'])
  if a['age'] is None or a['age']>=18:raise HTTPException(400,'מסמך הורה נדרש לקטינים בלבד')
  if document.content_type not in ('application/pdf','image/jpeg','image/png'):raise HTTPException(400,'יש לצרף PDF או תמונה')
  data=await document.read(3_000_001)
  if len(data)>3_000_000:raise HTTPException(413,'קובץ גדול מדי (עד 3MB)')
  c.execute('UPDATE admissions SET guardian_document=?,guardian_document_type=?,guardian_document_name=? WHERE id=?',(seal_bytes(data),document.content_type,document.filename[:120] if document.filename else 'document',aid))
 return {'ok':True}
@app.get('/api/admissions/{aid}/document')
def read_admission_document(aid:int,r:Request):
 u=auth(r)
 with db() as c:
  a=c.execute('SELECT * FROM admissions WHERE id=?',(aid,)).fetchone()
  if not a:raise HTTPException(404)
  order_access(c,u,a['order_id'])
  if not a['guardian_document']:raise HTTPException(404)
  return Response(unseal(a['guardian_document']),media_type=a['guardian_document_type'],headers={'Cache-Control':'no-store','Content-Disposition':'attachment; filename="guardian-document"'})
@app.get('/api/admissions/{aid}/pass')
def admission_pass(aid:int,r:Request):
 u=auth(r)
 with db() as c:
  a=c.execute('SELECT * FROM admissions WHERE id=?',(aid,)).fetchone()
  if not a:raise HTTPException(404)
  o=order_access(c,u,a['order_id'])
  e=c.execute('SELECT title FROM events WHERE id=?',(o['event_id'],)).fetchone()
  if o['status']!='confirmed':raise HTTPException(400,'יש לאשר את ההזמנה')
  if a['age'] is not None and a['age']<18 and not a['guardian_document']:raise HTTPException(400,'יש לצרף תעודת הורה וספח לפני הפקת הכרטיס')
  def p(s):return escape(str(s or '—'))
  notes=p(a['notes']) if a['notes'] else 'אין הערות נוספות'
  parent_note=('לקטין מתחת לגיל 18: יש להמציא הצהרת הורה חתומה, תעודה מזהה וספח למספר WhatsApp ‏0504313030, בצירוף שם המזמין.' if a['age'] is not None and a['age']<18 else '')
  eilat_note=('לתושב/ת אילת: יש להציג תעודה מזהה בכניסה. לילד/ה מתחת לגיל 16 יש לשלוח תעודת הורה וספח למספר WhatsApp ‏0504313030 בצירוף שם המזמין.' if a['eilat_resident'] else '')
  second_day = a['entry_type']=='26-27' or a['zone']=='VIP'
  second_day_html = '<div><b>יום שישי 27.11.2026: 11:30–15:00</b></div>' if second_day else ''
  standard_terms = '<div><b>קוד לבוש: לבן 🤍</b></div><div>הנהלת ההפקה שומרת לעצמה את הזכות לשנות את מיקום האירוע ו/או סידורי הישיבה בהתאם לצרכיה.</div><div>השובר אישי, שמי ואינו ניתן להעברה או לביטול, בכפוף להוראות הדין.</div><div>הכניסה מותנית בשובר תקף ובתעודה מזהה בהתאם להנחיות.</div><div><b>בילוי מהנה! H&amp;D Productions – חברים • מוזיקה • חוויה</b></div>'
  details=f'''<html lang="he" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>שובר כניסה</title><style>body{{font-family:Arial,sans-serif;max-width:520px;margin:24px auto;padding:20px;line-height:1.8}}h1{{color:#193c66}}.ticket{{border:2px solid #193c66;border-radius:16px;padding:24px}}.footer{{margin-top:22px;border-top:1px solid #aaa;padding-top:12px;white-space:pre-wrap}}@media print{{button{{display:none}}}}</style><div class="ticket"><h1>H&D Productions</h1><h2>{p(e['title'])}</h2><div>שם המזמין: {p(o['customer'])}</div><div>אורח/ת: {p(a['guest_name'])}</div><div>אזור: {p(a['zone'])} | כיסא: {p(a['seat'])}</div><div>שולחן: {p(a['table_name'])}</div><div>כניסה: {('26–27.11.2026' if a['entry_type']=='26-27' else '26.11.2026')}</div><div>תחילת אירוע: {p(a['event_time'])}</div>{second_day_html}<div>תושב אילת: {('כן' if a['eilat_resident'] else 'לא')}</div><section class="footer"><b>הערות והנחיות כניסה</b><div>{notes}</div><div>{eilat_note}</div><div>{parent_note}</div>{standard_terms}</section></div><p><button onclick="print()">הדפסה / שמירה כ-PDF</button></p></html>''' 
  return Response(details,media_type='text/html; charset=utf-8',headers={'Cache-Control':'no-store'})
