from flask import Flask, render_template, request, flash, redirect, url_for, session, send_file
from flask_caching import Cache
from werkzeug.utils import secure_filename
import os
from pred_api import read_data,grir_pred, read_dataframe_json, read_dataframe_dummy
from train import train_model

#Login Modules
from passlib.hash import pbkdf2_sha256
import uuid
from functools import wraps
import pymongo
import sys
from datetime import date, datetime
import json
import urllib.parse
import urllib3
from collections import OrderedDict
import re
from flask_wtf.csrf import CSRFProtect,CSRFError
from bson import ObjectId
from flask_mail import Mail, Message
from classes.constant import CONSTANT
from eda import get_charts

# Init
app = Flask(__name__)
app.secret_key = 'my_secret_key'
app.config.update(
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=True
    )

csrf = CSRFProtect()
csrf.init_app(app)

# configuration of mail
app.config['MAIL_SERVER']   =  CONSTANT['MAIL_SERVER']
app.config['MAIL_PORT']     =  CONSTANT['MAIL_PORT']
#app.config['MAIL_USERNAME'] =  CONSTANT['MAIL_USERNAME']
#app.config['MAIL_PASSWORD'] =  CONSTANT['MAIL_PASSWORD']
#app.config['MAIL_USE_TLS']  =  CONSTANT['MAIL_USE_TLS']
#app.config['MAIL_USE_SSL']  =  CONSTANT['MAIL_USE_SSL']

#app.config['WTF_CSRF_ENABLED'] = False
#app.config["WTF_CSRF_TIME_LIMIT"] = None
mail = Mail(app)

UPLOAD_FOLDER = './data/temp/'
DOWNLOAD_FOLDER = 'data\\output\\'
# app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Set maximum file size to 16 MB
app.config['UPLOAD_EXTENSIONS'] = {'csv','xlsx','xls'} #{'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_PATH'] = UPLOAD_FOLDER
app.config['DOWNLOAD_PATH'] = DOWNLOAD_FOLDER
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

cache = Cache(app, config={
    'CACHE_TYPE': 'simple',
    'CACHE_THRESHOLD': 1000  # Set the cache size limit to 1000 objects
})


#INIT DB connection
# Database
#client = pymongo.MongoClient('mongodb://%s:%s@%s/?authSource=%s'%(urllib.parse.quote_plus("gagan"), urllib.parse.quote_plus("gagan@123"), "127.0.0.1:27020", "DAT")) # Login for Josh
client = pymongo.MongoClient('localhost', 27017)
db = client.GRIR


######################LOGIN##############################

@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST')
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline'; style-src-elem 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.datatables.net https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src-elem 'self' 'unsafe-inline' 'unsafe-eval' https://code.jquery.com http://code.jquery.com https://cdn.datatables.net https://cdn.jsdelivr.net https://maxcdn.bootstrapcdn.com https://cdnjs.cloudflare.com; img-src 'self' data: https://cdn.datatables.net;"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, pre-check=0, post-check=0, max-age=0, s-maxage=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Allow'] = "GET, POST"
    return response

# Sample UI

# Decorators
def loginRequired(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'loggedIn' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')

    return wrap

@app.route('/', methods=['GET','POST'])
def login():
    error = None
    if 'loggedIn' in session:
        return redirect(url_for('home'))
    else:
        if request.method == 'POST':
            user = db.users.find_one({"username": request.form['username'],"isActive":1})
            if user: 
                beforeLoginAttempts = beforeLogin()
                pwExpiryCheck = pwExpiry()
                if pwExpiryCheck:
                    if beforeLoginAttempts:
                        if pbkdf2_sha256.verify(request.form['psw'], user['password']):
                            if user['isLoggedIn']==0:
                                session['loggedIn'] = True
                                session['user'] = user['username']
                                session['role'] = user['role']
                                session['site'] = user['site']
                                db.user_logs.insert_one({"username": request.form['username'],"lastLogin": datetime.now()})
                                db.users.update_one({"username":request.form['username']},{"$set": {"attempts":0,"lastLogin":datetime.now()}})
                                db.users.update_one({"username":request.form['username']},{"$set": {"isLoggedIn":1}})
                                return redirect(url_for('home'))
                            else:
                                error = "You are already logged in to other browser."
                        else:
                            attemptsCount = afterUnsuccessfulLogin()
                            if attemptsCount ==3:
                                error = 'You have reached the maximum number of login attempts. Please wait for 30 min or contact to administrator to unlock your account.'
                            else:
                                error = 'You have made '+str(attemptsCount)+' unsuccessful attempt(s). A maximum of 3 login attempts are permitted.'
                    else:
                        error = 'Your have reached the maximum number of login attempts. Please wait for 30 min or contact to administrator to unlock your account.'
                else:
                    error = 'Password is expired. Please reset you password using Forgot Password method'
            else:
                error = 'The username and/or password are incorrect. Please try again or contact to administrator.'
    return render_template('user/login.html', error=error)


#This function is calling in Login()
def afterUnsuccessfulLogin():
    user = db.users.find_one({"username": request.form['username']})
    attempts = user['attempts']+1
    db.users.update_one({"username":request.form['username']},{"$set": {"attempts":attempts,"lastLogin":datetime.now()}})
    return attempts

def pwExpiry():
    user = db.users.find_one({"username": request.form['username']})

    currentDate = datetime.today().date()
    pwCreatedDate = user['pwCreated'].date()
    dateDiff =  (currentDate - pwCreatedDate).days
    pwExpDays = 90-dateDiff
    if dateDiff > 90:
        return False
    elif 84 < dateDiff <= 90:
        msg = Message(
                'Reset your password soon!',
                sender = CONSTANT['FROM_EMAIL'],
                recipients = [request.form['username']]
            )
        msg.body = '\nDear user,\n'+'\n'+'Your existing password will expire within '+str(pwExpDays)+' Days. Kindly reset your password!'+'\n'+'\nThank you,\nTeam DAT'
        #mail.send(msg)
        return True
    else:
        return True

#This function is calling in Login()
def beforeLogin(): 
    user = db.users.find_one({"username": request.form['username']})

    if user['attempts'] >=3 :
        currentTime = datetime.now().timestamp()
        lastLoginTime = user['lastLogin'].timestamp()
        timeDiff =  currentTime - lastLoginTime
        timeDiff = timeDiff/60
        if timeDiff < 30:
            return False
        else:
            db.users.update_one({"username":request.form['username']},{"$set": {"attempts":0,"lastLogin":datetime.now()}})
            return True
    else:
        return True


@app.route('/user/signup', methods=['GET','POST'])
def signup():
    error = None
    #print(request.url_root)
    if request.method == 'POST':

        user = {
            #"_id": uuid.uuid4().hex,
            "username": request.form['username'],
            "password": request.form['psw'],
            "role": "",
            "site":"",
            "isLoggedIn":0,
            "attempts":0,
            "lastLogin":"",
            "isActive":0,
            "pwCreated": datetime.today()
        }

        # Encrypt the password
        userExist = db.users.find_one({"username": user['username']})
        if userExist is not None:
            if 'username' in userExist and userExist['isActive']==0 :
                error = 'Your account is not activated. Please contact to administrator.'
            elif 'username' in userExist:
                error = "Authentication failed. Please try again."
        else:
            isValidPassword = password_check(user['password'])
            if isValidPassword:
                #print(user['username'].lower())
                if user['password'].lower()!=user['username'].lower()[:-4]:
                    user['password'] = pbkdf2_sha256.encrypt(user['password'])
                    user['code'] = randomString()
                    db.users_pw_info.find({})
                    db.users_pw_info.insert_one({"username":user['username'],"psw1":user['password'],"psw2":"","psw3":"","psw4":"","psw5":"","pwChange":0})
                    if db.users.insert_one(user):
                        msg = Message(
                                'User registration activation email',
                                sender = CONSTANT['FROM_EMAIL'],
                                recipients = [user['username']]
                            )
                        msg.body = '\nDear user,\n'+'\n'+'Please click on the link below to activate your account\n'+'\n'+request.url_root+'user/activate?email='+ urllib.parse.quote_plus(user['username'])+'&code='+user['code'] +'\n'+'\nThank you,\nTeam DAT'
                        #mail.send(msg)
                        flash("An email with a verification link sent to "+  user['username'])
                        return redirect(url_for('signup'))
                else:
                    error = 'Please use different password'
            else:
                error = 'Password must contain at least 8 characters, atmost 18 characters,  including uppercase, lowercase letters, numbers and special characters @$!#%*?&'
    return render_template('user/signup.html', error=error)

def password_check(password):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """
    reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,18}$"
    matchRe = re.compile(reg)
    res = re.search(matchRe, password)
    if res:
        return True
    else:
        return False

def removeCollections():
    db[session['user']+"_current"].delete_one({})
    db[session['user']+"_unique_current"].delete_one({})
    db[session['user']+"_remove_current"].delete_one({})
    data = {}
    
@app.route('/signout', methods=['GET', 'POST'])
def signout():
    if request.method=="GET":
        idle = request.args.get('idle')
        if idle==str(1):
            flash("Your session has expired! Please login again")
        else:
            flash("You are logged out!")
    db.users.update_one({"username":session['user']},{"$set": {"isLoggedIn":0}})
    session.clear()
    return redirect(url_for('login'))
    #return render_template('user/login.html', error=error)


@app.route('/user/profilePassword', methods=['GET', 'POST'])
@loginRequired
def profilePassword():
    error = None
    #print(userPwInfo)
    if request.method == 'POST':
        userInfo = db.users.find_one({"username": session['user'],"isActive":1})
        userPwInfo = db.users_pw_info.find_one({"username":session['user']})
        if pbkdf2_sha256.verify(request.form['oldPsw'], userInfo['password']):
            isValidPassword = password_check(request.form['psw'])
            if request.form['psw'] == request.form['oldPsw']:
                error = "Your new password should not be same as old password"
            else:
                if isValidPassword:
                    if request.form['psw'].lower()!=session['user'].lower()[:-9]:
                        password = pbkdf2_sha256.encrypt(request.form['psw'])
                        #print(pbkdf2_sha256.decrypt(password))
                        #print(userPwInfo.values())
                        #print(list(userPwInfo.values())[2:])
                        for i in range(1,len(list(userPwInfo.values()))):
                            if "pbkdf2-sha256" in str(list(userPwInfo.values())[i]):
                                if pbkdf2_sha256.verify(request.form['psw'], list(userPwInfo.values())[i]):
                                    error = 'Please try again using some other password'
                                    return render_template('user/profile_password.html', error=error)
                                else:
                                    continue
                            else:
                                continue
                        if db.users.update_one({"username":session['user']},{"$set": {"password":password,"pwCreated":datetime.today()}}):
                            flash('Your password has been updated successfully!')
                            if userPwInfo.get("pwChange")==0:
                                db.users_pw_info.update_one({"username":session['user']},{"$set": {"psw2":password,"pwChange":1}})                                
                            elif userPwInfo.get("pwChange")==1:
                                db.users_pw_info.update_one({"username":session['user']},{"$set": {"psw3":password,"pwChange":2}})
                            elif userPwInfo.get("pwChange")==2:
                                db.users_pw_info.update_one({"username":session['user']},{"$set": {"psw4":password,"pwChange":3}})
                            elif userPwInfo.get("pwChange")==3:
                                db.users_pw_info.update_one({"username":session['user']},{"$set": {"psw5":password,"pwChange":4}})
                            elif userPwInfo.get("pwChange")==4:
                                db.users_pw_info.update_one({"username":session['user']},{"$set": {"psw1":password,"pwChange":0}})
    
                            
                    else:
                        error = 'Username cannot be used as password'
                else:
                    error = 'Password must contain at least 8 characters, atmost 18 characters, including uppercase, lowercase letters, numbers and special characters @$!#%*?&'
        else:
            error = 'Old password does not match with existing password'
    return render_template('user/profile_password.html', error=error)

@app.route('/user/userInfo', methods=['GET', 'POST'])
@loginRequired
def userInfo():
    userData = db.users.find({})
    return render_template('user/userInfo.html', userData=userData)

@app.route('/user/updateUserAttempts', methods=['GET', 'POST'])
def updateUserAttempts():
    if request.method == 'POST':
        objId = request.form['userId']
        if db.users.update_one({"_id":ObjectId(objId)},{"$set": {"attempts":0,"lastLogin":datetime.now()}}):
            return {"response":"Success"}

@app.route('/user/activate', methods=['GET', 'POST'])
def activate():
    msg = 'fail'
    if request.method=="GET":
        code = request.args.get('code')
        email = request.args.get('email')
        email = urllib.parse.unquote_plus(email)
        if db.users.find_one({"username": email,"code":code}):
            if db.users.update_one({"username":email,"code":code},{"$set": {"isActive":1}}):
                msg = "success"
    return render_template('user/activate.html', msg=msg)

@app.route('/user/forgotPassword', methods=['GET', 'POST'])
def forgotPassword():
    error = None
    if request.method=="POST":
        email = request.form['username']
        userExist = db.users.find_one({"username": email})
        if userExist is None:
            error = "This email is not registered with us. Please go to sign up for registration"
        else:
            code = randomString()
            if db.users.update_one({"username":email},{"$set": {"code":code}}):
                msg = Message(
                        'User forgot password activation link',
                        sender = CONSTANT['FROM_EMAIL'],
                        recipients = [email]
                    )
                msg.body = '\nDear user,\n'+'\n'+'Please use the below link to update your password\n'+'\n'+request.url_root+'user/changePassword?email='+ urllib.parse.quote_plus(email)+'&code='+code+'\n'+'\nThank you,\nTeam DAT'
                #mail.send(msg)
                flash("An email with a forgot password activation link sent to "+  email)
                return redirect(url_for('forgotPassword'))
    return render_template('user/forgot_password.html', error=error)

@app.route('/user/changePassword', methods=['GET', 'POST'])
def changePassword():
    error = None
    data={}
    if request.method=="GET":
        data['code'] = request.args.get('code')
        email = request.args.get('email')
        data['email'] = urllib.parse.unquote_plus(email)
    
    if request.method == 'POST':
        user = {
            "password": request.form['psw'],
            "username": request.form['email'],
            "code": request.form['code'],
        }
        userPwInfo = db.users_pw_info.find_one({"username":user['username']})
        isValidPassword = password_check(user['password'])
        if isValidPassword:
            #print(user['password'].lower())
            #print(user['username'].lower()[:-4])
            if user['password'].lower()!=user['username'].lower()[:-9]:
                user['password'] = pbkdf2_sha256.encrypt(user['password'])
                if db.users.find_one({"username": user['username'],"code":user['code']}):
                    for i in range(1,len(list(userPwInfo.values()))):
                        if "pbkdf2-sha256" in str(list(userPwInfo.values())[i]):
                            if pbkdf2_sha256.verify(request.form['psw'], list(userPwInfo.values())[i]):
                                error = 'Please try again using some other password'
                                return render_template('user/change_password.html', error=error, data=data)
                            else:
                                continue
                        else:
                            continue
                    if db.users.update_one({"username":user['username']},{"$set": {"password":user['password'],"pwCreated":datetime.today()}}):
                        flash('Your password has been updated successfully! Now you can login')
                        if userPwInfo.get("pwChange")==0:
                            db.users_pw_info.update_one({"username":user['username']},{"$set": {"psw2":user['password'],"pwChange":1}})                                
                        elif userPwInfo.get("pwChange")==1:
                            db.users_pw_info.update_one({"username":user['username']},{"$set": {"psw3":user['password'],"pwChange":2}})
                        elif userPwInfo.get("pwChange")==2:
                            db.users_pw_info.update_one({"username":user['username']},{"$set": {"psw4":user['password'],"pwChange":3}})
                        elif userPwInfo.get("pwChange")==3:
                            db.users_pw_info.update_one({"username":user['username']},{"$set": {"psw5":user['password'],"pwChange":4}})
                        elif userPwInfo.get("pwChange")==4:
                            db.users_pw_info.update_one({"username":user['username']},{"$set": {"psw1":user['password'],"pwChange":0}})
                        return redirect(url_for('login'))
                else:
                    error = 'It seems that you are not authenticated, Please contact to administrator'
            else:
                error = 'Username cannot be used as password'
        else:
            error = 'Password must contain at least 8 characters, atmost 18 characters, including uppercase, lowercase letters, numbers and special characters @$!#%*?&'
    return render_template('user/change_password.html', error=error, data=data)

@app.route('/user/userManagement', methods=['GET', 'POST'])
def userManagement():
    error = None
    data={}
    userdb = db.users.find()
    user_list = []
    for users in userdb:
        user_list.append(users)
    
    if request.method == 'POST':
        user = {
            "username": request.form['username'],
            "role": request.form['role'],
            "site": request.form['site']
        }

        if db.users.find_one({"username": user['username']}):
            if db.users.update_one({"username":user['username']},{"$set": {"role":user['role'],"site":user['site']}}):
                flash('User information added successfully!')

    return render_template('user/userManagement.html', error=error, user_list=user_list)

def randomString(string_length=6):
    """Returns a random string of length string_length."""
    random = str(uuid.uuid4()) # Convert UUID format to a Python string.
    random = random.upper() # Make all characters uppercase.
    random = random.replace("-","") # Remove the UUID '-'.
    return random[0:string_length] # Return the random string.



# @app.route('/home')
# @loginRequired
# def home():
#     removeCollections()
#     return render_template('home.html')

######################LOGIN##############################

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['UPLOAD_EXTENSIONS']

@app.route('/home')
def home():
    item = cache.get('test_data')
    if item is not None and len(item)>0:
        print("cache has test data")
        df = cache.get("test_data")
        print(df)
    else:
        print('no cache data')
        df = read_dataframe_dummy()
        cache.set("test_data",df)
        print('test data cached')
    return render_template('home.html')

@app.route('/test', methods=['GET'])
def test():
    #load data into a DataFrame object:
    item = cache.get('test_data')
    if item is not None and len(item)>0:
        print("cache has test data")
        df = cache.get("test_data")
        print(df)
    else:
        print('no cache data')
        df = read_dataframe_dummy()
        cache.set("test_data",df)
        print('test data cached')
    return render_template('test.html', data=df.to_html(table_id='gr_table'))

@app.route('/data_info')
@loginRequired
def data_info():
    # sample data for table
    sess_data = session["grir"]
    print(f"url_action {sess_data['url_action']}")
    # data_list = [
    #     # {'name': 'John Doe', 'age': 30},
    #     # {'name': 'Jane Smith', 'age': 25},
    #     # {'name': 'Bob Johnson', 'age': 45}
    #     data
    # ]
    
    return render_template('data_info.html', data=sess_data)

@app.route('/upload', methods=['POST'])
@csrf.exempt
def upload():
    try:
        files = request.files.getlist('file')
        if len(files) > 3:
            flash('Maximum of 5 files allowed')
            return redirect(request.url)
        for file in files:
            print(file.filename)
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if not allowed_file(file.filename):
                flash('Invalid file extension')
                return redirect(request.url)
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_PATH'], filename))
            print(f"filename {filename}")
            file_type = request.form['options']
            print(f"file_type  {file_type}")
            if file_type=='grir_train':
                df = read_data(os.path.join(app.config['UPLOAD_PATH'],filename),category='train')
                # Store the train data in the cache with a unique key
                cache.set('train_data', df)
                print("cache train data successfull")
                session["grir"] = {"table_data":df.head(10).to_html(classes='table table-light table-striped',table_id='gr_table'),"train":{},"url_action":"train"}
                session["grir"]["train"]={"train_filename":filename,"model_name":"random_forest"}
            else:
                df = read_data(os.path.join(app.config['UPLOAD_PATH'],filename))
                cache.set('test_data', df)
                print("cache test data successfull")
                session["grir"] = {"table_data":df.head(10).to_html(classes='table table-light table-striped',table_id='gr_table'),"test":{},"url_action":"output"}
                session["grir"]["test"]={"filename":filename,"model_name":"random_forest"}
        print('Files uploaded successfully!')
        print(session['grir'])
        return redirect(url_for('data_info'))
    except Exception as e:
        flash(f'Error uploading file: {str(e)}')
        return redirect(request.url)


# @app.route('/grir_predictor', methods=['GET'])
def grir_predictor():
    df_output = []
    try:
        response_obj = {"msg":""}
        if session["grir"]:
            requestJson = session["grir"]["test"]
            if "filename" in requestJson.keys():
                filename = requestJson.get("filename")
                model_name = requestJson.get("model_name")
                print(f"filepath {os.path.join(app.config['UPLOAD_PATH'],filename)}")
                item = cache.get('test_data')
                if item is not None and len(item)>0:
                    print("cache has test data")
                    df = cache.get("test_data")#read_dataframe_json(cache.get("test_data", None))
                else:
                    print("cache hasnt test data")
                    df = read_data(os.path.join(app.config['UPLOAD_PATH'],filename))
                    cache.set("test_data",df)
                print(df.shape)
                if len(df.columns) > 0:
                    # df=df.dropna(subset=['HFM'])
                    df=df.dropna(subset=["Status"])
                    print(f"after dropna {df.shape}")
                    df_pred_output = grir_pred(df=df,outputpath=app.config['DOWNLOAD_PATH'],fname=filename,model_name=model_name)
                    session["grir"] = {}
                    session["grir"]["data"] = {"empty":"empty"}
                    response_obj['filename'] = df_pred_output["filename"]
                    response_obj['msg'] = 'GRIR predictions comepleted use the filename to get the file'
                    df_output = df_pred_output["df_pred_output"]
                    cache.set("test_pred_data",df_pred_output["df_pred_output"])
                else:
                    response_obj = {"msg":"No data found. Please upload records with valid data"}
                session["grir"]["test"] = response_obj
                # return redirect(url_for('output')) 
            else:
                response_obj = {"msg":"Please provide valid filename"}
                session["grir"]["test"] = response_obj
                # return redirect(url_for('output'))
        else:
            response_obj = {"msg":"missing input parameters. Please pass all mandatory params"}
        session["grir"]["test"] = response_obj
        # return redirect(url_for('output'))
        return df_output
    except Exception as e:
        print(f'Error grir_predictor: {str(e)}')
        # return redirect(request.url)
    return []

@app.route('/output', methods=['GET'])
@loginRequired
def output():
    # retrieve dataframe from session and parse from JSON
    # df = read_dataframe_json(session['grir']['data'])
    df_output = grir_predictor()
    datalist = {"data":[session["grir"]]}
    # df = read_dataframe_dummy()
    datalist["table"] = df_output.head(50).to_html(classes='table table-light table-striped',table_id='gr_table') if len(df_output)>0 else df_output
    # render the dataframe as an HTML table using Jinja2 templates
    return render_template('output.html', data=datalist)


@app.route('/download', methods=['GET'])
@loginRequired
def download():
    # retrieve dataframe from session and parse from JSON
    print(session["grir"])
    data = session["grir"]["test"]
    file_loc = os.path.join(app.config['DOWNLOAD_PATH'], data["filename"])
    download_template_name = "GRIR_commentary_output"
    return send_file(file_loc,attachment_filename= f'{download_template_name}.xlsx',as_attachment = True)

### Train Model
def train_model_grir():
    df_output = {}
    try:
        response_obj = {"msg":""}
        if session["grir"]:
            requestJson = session["grir"]["train"]
            if "train_filename" in requestJson.keys():
                filename = requestJson.get("train_filename")
                # model_name = requestJson.get("model_name")
                print(f"filepath {os.path.join(app.config['UPLOAD_PATH'],filename)}")
                item = cache.get('train_data')
                if item is not None and len(item)>0:
                    print("cache has train data")
                    df = cache.get("train_data")#read_dataframe_json(cache.get("train_data"))
                else:
                    print("cache hasnt train data")
                    df = read_data(os.path.join(app.config['UPLOAD_PATH'],filename),category='train')
                    cache.set("train_data",df)
                print(f"train data:: {df.shape}")
                if len(df.columns) > 0:
                    # df=df.dropna(subset=['HFM'])
                    # df=df.dropna(subset=["Status"])
                    # print(f"after dropna {df.shape}")
                    accuracy_sc = train_model(df=df)
                    session["grir"] = {}
                    session["grir"]["train"] = accuracy_sc
                    response_obj["train"] = accuracy_sc
                    # response_obj['filename'] = df_pred_output["filename"]
                    response_obj['msg'] = 'Model train completed. use the saved pickle file prediction'
                    df_output = response_obj
                else:
                    response_obj = {"msg":"No data found. Please upload records with valid data"}
                session["grir"]["train"] = response_obj
                # return redirect(url_for('output')) 
            else:
                response_obj = {"msg":"Please provide valid filename"}
                session["grir"]["train"] = response_obj
                # return redirect(url_for('output'))
        else:
            response_obj = {"msg":"missing input parameters. Please pass all mandatory params"}
        session["grir"]["train"] = response_obj
        # return redirect(url_for('output'))
        return df_output
    except Exception as e:
        print(f'Error train: {str(e)}')
        # return redirect(request.url)
    return {"msg":"something went wrong"}

@app.route('/train', methods=['GET'])
@loginRequired
def train():
    # retrieve dataframe from session and parse from JSON
    # df = read_dataframe_json(session['grir']['data'])
    df_output = train_model_grir()
    print(session["grir"]["train"])
    datalist = session["grir"]["train"]["train"]
    # df = read_dataframe_dummy()
    # datalist["table"] = df_output.head(50).to_html(classes='table') if len(df_output)>0 else df_output
    # render the dataframe as an HTML table using Jinja2 templates
    return render_template('train.html', data=datalist)

#EDA

def eda_data():
    df_output = {"script":None,"div":None}
    try:
        response_obj = {"msg":""}
        if session["grir"]:
            requestJson = session["grir"]["test"]
            if "filename" in requestJson.keys():
                filename = requestJson.get("filename")
                # model_name = requestJson.get("model_name")
                print(f"filepath {os.path.join(app.config['UPLOAD_PATH'],filename)}")
                item = cache.get('test_pred_data')
                if item is not None and len(item)>0:
                    print("cache has test data")
                    df = cache.get("test_pred_data")#read_dataframe_json(cache.get("train_data"))
                else:
                    print("cache hasnt train data")
                    df = read_data(os.path.join(app.config['UPLOAD_PATH'],filename))
                    cache.set("test_pred_data",df)
                print(f"test data:: {df.shape}")
                if len(df.columns) > 0:
                    # df=df.dropna(subset=['HFM'])
                    # df=df.dropna(subset=["Status"])
                    # print(f"after dropna {df.shape}")
                    scripts,divs = get_charts(df=df)
                    session["grir"] = {}
                    session["grir"]["eda"] = (scripts,divs)
                    response_obj["eda"] = (scripts,divs)
                    response_obj["script"] = scripts
                    response_obj["div"] = divs
                    # response_obj['filename'] = df_pred_output["filename"]
                    response_obj['msg'] = 'Model eda completed.'
                    df_output["script"] = scripts
                    df_output["div"] = divs
                else:
                    response_obj = {"msg":"No data found. Please upload records with valid data"}
                session["grir"]["eda"] = response_obj
                # return redirect(url_for('output')) 
            else:
                response_obj = {"msg":"Please provide valid filename"}
                session["grir"]["eda"] = response_obj
                # return redirect(url_for('output'))
        else:
            response_obj = {"msg":"missing input parameters. Please pass all mandatory params"}
        session["grir"]["eda"] = response_obj
        # return redirect(url_for('output'))
        return df_output
    except Exception as e:
        print(f'Error eda: {str(e)}')
        # return redirect(request.url)
    return {"msg":"something went wrong"}

@app.route('/eda', methods=['GET'])
@loginRequired
def eda():
    eda_output = eda_data()
    scripts=eda_output["script"]
    divs = eda_output["div"]
    # Return all the charts to the HTML template
    return render_template(
        template_name_or_list='charts.html',
        script=scripts,
        div=divs,
    )


###############################
# Handling error 404, 405, 500 and displaying relevant web page
@app.errorhandler(404)
def not_found_error(error):
    return render_template("error/404.html")

@app.errorhandler(405)
def not_found_error(error):
    return render_template("error/405.html")

@app.errorhandler(500)
def not_found_error(error):
    return render_template("error/500.html")

#@app.errorhandler(CSRFError)
#def handle_csrf_error(e):
#    return render_template('error/csrf_error.html', reason=e.description), 400

#@app.errorhandler(302)
#def not_found_error(error):
#    return render_template("error/302.html")

if __name__ == '__main__':
    app.run(debug=True,port=5000)
