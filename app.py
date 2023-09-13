from flask import Flask,jsonify,request,flash,send_from_directory
import secrets
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import json
from flask_bcrypt import Bcrypt,generate_password_hash
from flask_session import Session
from datetime import datetime, timedelta, timezone
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, \
                               unset_jwt_cookies, jwt_required, JWTManager
from PIL import Image
import fitz
import io
import pandas as pd

app = Flask(__name__)
app.app_context().push()

secret_key = secrets.token_hex(16)
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER']='static/images'
db = SQLAlchemy(app)
bcrypt=Bcrypt(app) 
migrate = Migrate(app, db)
jwt = JWTManager(app)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

CORS(app, origins=["http://localhost:3000"])


class User(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   email = db.Column(db.String(80), unique=True, nullable=False)
   password = db.Column(db.String(128), nullable=False) 
   username=db.Column(db.String(200), nullable=False)
   description=db.Column(db.Text,default="No description provided")
   occupation=db.Column(db.String(128),default="Unknown occupation")
   image=db.Column(db.String(255),default="default_profile_image.jpg")
   university=db.Column(db.String(255), nullable=False)
   posts = db.relationship('Post', backref='author', lazy=True)
   
   def __repr__(self):
        return f"User('{self.username}')"

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image=db.Column(db.String(255))
    date_posted = db.Column(db.DateTime,  default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)

db.create_all() 

ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    university=data.get('university')
    username=data.get('username')
    print(username)
    print(university)

    if not email or not password or not university or not username :
        return jsonify({'error': 'All fields are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400
    

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(email=email,  password=hashed_password, university=university,username=username)
    db.session.add(user)
    db.session.commit()
    flash('Your account has been created! You are now able to log in', 'success')
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])

def login():
    data = request.get_json()
    
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=email)
        response = {"message": "Login Successful", "access_token": access_token}
        return jsonify(response), 200
        
    else:
         
        flash('Login Unsuccessful. Please check email and password', 'danger')
        return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/create_post', methods=['POST','GET'])
@jwt_required()
def create():
    if request.method=='POST':
        current_user = get_jwt_identity()
        data = request.form
        print("Received data:", data)
        content = data.get('content')
        image=request.files.get('image')
       
        if content and image:
          
          
             if image.filename.endswith('.pdf'):
                pdf_filename = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
                image.save(pdf_filename)

              
                pdf_document = fitz.open(pdf_filename)
                images = []
                for page_num in range(pdf_document.page_count):
                    page = pdf_document.load_page(page_num)
                    image_bytes = page.get_pixmap().tobytes()
                    image = Image.open(io.BytesIO(image_bytes))
                    image_filename = f"page_{page_num}.png"
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                    images.append(image_filename)

               
                post = Post(content=content, image=','.join(images), user_id=current_user)
                db.session.add(post)
                db.session.commit()
                
                return jsonify({'message': 'Post created with PDF images'}), 200
             else:
                image_filename=os.path.join(app.config['UPLOAD_FOLDER'],image.filename)
                image.save(image_filename)
                post=Post(content=content,image=image.filename,user_id=current_user)
                db.session.add(post)
                db.session.commit()
                return jsonify({'message':'post created '}),200
        else:
            return jsonify({'message':'content required'}),201
  

    elif request.method=='GET':
        current_user = get_jwt_identity()
        page = request.args.get('page', default=1, type=int)
        posts_per_page = request.args.get('posts_per_page', default=10, type=int)

      
        total_posts = Post.query.count()
        total_pages = (total_posts + posts_per_page - 1) 
        offset = (page - 1) * posts_per_page

        posts = Post.query.order_by(Post.date_posted.desc()).all()
        post_list = []
        for post in posts:
            user=User.query.filter_by(email=post.user_id).first()
            post_data = { 
                'id': post.id,
                'content': post.content,
                'image':post.image,
                'username':user.username,
                'userimage':user.image,
                'email':user.email
            }
            post_list.append(post_data)
        
        return jsonify({'posts': post_list}), 200


@app.route('/userprofile', methods=['POST', 'GET'])
@jwt_required()
def send_username():
    global emailitem 

    

    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        emailitem = email  
        print(f'Received email: {email}')

       
        return jsonify({'message': 'Email received'}), 200

    elif request.method == 'GET':
        user = User.query.filter_by(email=emailitem).first()
        print(user)
        user_post=Post.query.filter_by(user_id=user.email).all()
        post = [{'id': post.id, 'content': post.content,'image':post.image} for post in user_post]
        return jsonify({'username': user.username,'occupation':user.occupation,'email':user.email,'image':user.image,'posts':post}), 200





@app.route('/delete_post/<int:post_id>', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    user_id = get_jwt_identity()
    post = Post.query.filter_by(id=post_id, user_id=user_id).first()
    
    if post:
        db.session.delete(post)
        db.session.commit()
        return jsonify({'message': 'Post deleted successfully'}), 200
    else:
        return jsonify({'message': 'Post not found or not authorized'}), 404


@app.route('/user_post',methods=['GET'])
@jwt_required()
def user_post():
    user_id = get_jwt_identity()
    user_posts = Post.query.filter_by(user_id=user_id).all()
    posts = [{'id': post.id, 'content': post.content,'image':post.image} for post in user_posts]
    return jsonify(posts)



@app.route('/account', methods=['GET'])
@jwt_required()
def account():
    current_user=get_jwt_identity()
    user=User.query.filter_by(email=current_user).first()
    
    user_data = {
            'username': user.username,
            'occupation':user.occupation,
            'image':user.image,
            'email':user.email
        }
    
    return jsonify({'user': user_data}), 200



@app.route('/update_profile',methods=['POST'])
@jwt_required()
def update_profile():
    user_id=get_jwt_identity()
    data=request.form 
    username=data.get('username')
    description=data.get('description')
    occupation=data.get('occupation')
    image=request.files.get('image')
    print(image)
    print(data)
    if not username:
        user=User.query.filter_by(email=user_id).first()
        username=user.username

    if image:
         image_filename=os.path.join(app.config['UPLOAD_FOLDER'],image.filename)
         image.save(image_filename)
   
    user = User.query.filter_by(email=user_id).first()
    print(user)
    if user is None:
     return jsonify({'message': 'User not found'}), 404
    user.username=username 
    user.occupation=occupation
    user.description=description
    user.image=image.filename
    db.session.commit()
    return jsonify({'message':'profile updated successfully'}),200

 



@app.route('/static/images/<filename>',methods=['GET'])

def uploaded_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],filename)     





@app.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response


if __name__ == '__main__':
   app.run(debug=True)
