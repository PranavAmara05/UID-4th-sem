from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
from bson import ObjectId
from bson.json_util import dumps
import base64
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["farm_connect"]
farmers = db["farmers"]
sellers = db["sellers"]
admins = db["admins"]
users = db["users"]
crops = db["crops"]
products = db["products"]
user_orders = db["user_orders"]

app.secret_key = 'KrishiSetu'

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/farmer')
def farmer_dashboard():
    if 'user_id' not in session or session['user_role'] != 'farmer':
        return redirect('/')
    farmer_id = ObjectId(session['user_id'])
    farmer = db.farmers.find_one({'_id': farmer_id})
    crop_list = list(db.crops.find({"farmer_id": farmer_id}))

    return render_template('farmer1.html', farmer=farmer, crops=crop_list)

@app.route('/seller')
def seller_dashboard():
    if 'user_id' not in session or session['user_role'] != 'seller':
        return redirect('/')
    seller_id = ObjectId(session['user_id'])  # Convert to ObjectId
    seller_products = list(products.find({"seller_id": seller_id}))  # Fetch products for this seller
    # Convert ObjectId to string for JSON serialization
    for product in seller_products:
        product['_id'] = str(product['_id'])
        product['seller_id'] = str(product['seller_id'])
    return render_template('seller1.html', products=seller_products)

@app.route('/user')
def user_dashboard():
    if 'user_id' not in session or session['user_role'] != 'user':
        return redirect('/')
    user_id = ObjectId(session['user_id'])
    user = db.users.find_one({'_id': user_id})
    return render_template('user1.html', user=user)

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session['user_role'] != 'admin':
        return redirect('/')
    total_farmers = farmers.count_documents({})
    total_sellers = sellers.count_documents({})
    total_users = users.count_documents({})
    return render_template('admin1.html',total_farmers=total_farmers, total_sellers=total_sellers, total_users=total_users)

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/logout')
def logout():
    session.clear()
    return render_template('logout.html')

@app.route('/seller_profile')
def seller_profile():
    return render_template('seller_profile.html')

@app.route('/user_profile')
def user_profile():
    return render_template('user_profile.html')

@app.route('/farmer_profile')
def farmer_profile():
    return render_template('farmer_profile.html')

@app.route('/admin_profile')
def admin_profile():
    return render_template('admin_profile.html')

@app.route('/signup/farmer', methods=['POST'])
def signup_farmer():
    data = request.get_json()
    existing_user = farmers.find_one({"email": data['email']})
    if existing_user:
        return jsonify({'status': 'fail', 'message': 'Email already registered'}), 409

    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    farmers.insert_one({
        "name": data['name'],
        "phone": data['phone'],
        "email": data['email'],
        "land": data['land'],
        "village": data['village'],
        "state": data['state'],
        "pincode": data['pincode'],
        "password": hashed_pw
    })
    return jsonify({'status': 'success', 'message': 'Farmer account created'}), 201

@app.route('/login/farmer', methods=['POST'])
def login_farmer():
    data = request.get_json()
    user = farmers.find_one({"email": data['email']})
    if user and bcrypt.check_password_hash(user['password'], data['password']):
        session['user_id'] = str(user['_id'])
        session['user_role'] = 'farmer'
        return jsonify({'status': 'success', 'message': 'Login successful', 'redirect': '/farmer'}), 200
    return jsonify({'status': 'fail', 'message': 'Invalid credentials'}), 401

@app.route('/signup/seller', methods=['POST'])
def signup_seller():
    data = request.get_json()
    existing_user = sellers.find_one({"email": data['email']})
    if existing_user:
        return jsonify({'status': 'fail', 'message': 'Email already registered'}), 409

    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    sellers.insert_one({
        "name": data['name'],
        "phone": data['phone'],
        "email": data['email'],
        "gst": data['gst'],
        "village": data['village'],
        "state": data['state'],
        "pincode": data['pincode'],
        "password": hashed_pw
    })
    return jsonify({'status': 'success', 'message': 'Seller account created'}), 201

@app.route('/login/seller', methods=['POST'])
def login_seller():
    data = request.get_json()
    user = sellers.find_one({"email": data['email']})
    if user and bcrypt.check_password_hash(user['password'], data['password']):
        session['user_id'] = str(user['_id'])
        session['user_role'] = 'seller'
        return jsonify({'status': 'success', 'message': 'Login successful'}), 200
    return jsonify({'status': 'fail', 'message': 'Invalid credentials'}), 401

@app.route('/signup/user', methods=['POST'])
def signup_user():
    data = request.get_json()
    existing_user = users.find_one({"email": data['email']})
    if existing_user:
        return jsonify({'status': 'fail', 'message': 'Email already registered'}), 409

    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    users.insert_one({
        "name": data['name'],
        "phone": data['phone'],
        "email": data['email'],
        "address": data['address'],
        "password": hashed_pw
    })
    return jsonify({'status': 'success', 'message': 'User account created'}), 201

@app.route('/login/user', methods=['POST'])
def login_user():
    data = request.get_json()
    user = users.find_one({"email": data['email']})
    if user and bcrypt.check_password_hash(user['password'], data['password']):
        session['user_id'] = str(user['_id'])
        session['user_role'] = 'user'
        return jsonify({'status': 'success', 'message': 'Login successful', 'redirect': '/user'}), 200
    return jsonify({'status': 'fail', 'message': 'Invalid credentials'}), 401

@app.route('/login/admin', methods=['POST'])
def login_admin():
    data = request.get_json()
    user = admins.find_one({"email": data['email']})
    if user and bcrypt.check_password_hash(user['password'], data['password']):
        session['user_id'] = str(user['_id'])
        session['user_role'] = 'admin'
        return jsonify({'status': 'success', 'message': 'Login successful'}), 200
    return jsonify({'status': 'fail', 'message': 'Invalid credentials'}), 401

@app.route('/add-crop', methods=['POST'])
def add_crop():
    if 'user_id' not in session or session.get('user_role') != 'farmer':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    crop_name = request.form.get('cropName')
    quantity = request.form.get('quantity')
    price = request.form.get('price')
    
    if not all([crop_name, quantity, price]):
        return jsonify({'success': False, 'message': 'Missing data'}), 400

    crop_data = {
        "farmer_id": ObjectId(session['user_id']),
        "name": crop_name,
        "quantity": int(quantity),
        "price": int(price),
    }
    crops.insert_one(crop_data)
    return jsonify({'success': True, 'message': 'Crop added successfully'})

@app.route('/get-crops', methods=['GET'])
def get_crops():
    try:
        crop_list = list(db.crops.find())
        print("Crops fetched from database:", crop_list)  # Debug log
        return jsonify({'success': True, 'crops': dumps(crop_list)}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/add-product", methods=["POST"])
def add_product():
    try:
        # Ensure seller is logged in
        if 'user_id' not in session or session.get('user_role') != 'seller':
            return jsonify({"message": "Unauthorized"}), 401

        seller_id = ObjectId(session['user_id'])  # Get seller's ObjectId

        # Get form data
        name = request.form.get("name")
        category = request.form.get("category")
        price = float(request.form.get("price"))
        quantity = int(request.form.get("quantity"))
        unit = request.form.get("unit")
        description = request.form.get("description")
        image_file = request.files.get("image")
        image_data = None
        if image_file:
            image_data = base64.b64encode(image_file.read()).decode("utf-8")

        # Add seller_id to the product document
        product = {
            "seller_id": seller_id,
            "name": name,
            "category": category,
            "price": price,
            "quantity": quantity,
            "unit": unit,
            "description": description,
            "image_base64": image_data
        }
        products.insert_one(product)
        return jsonify({"message": "Product added successfully"}), 201
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"message": f"Failed to add product: {str(e)}"}), 500
    
@app.route('/get-products', methods=['GET'])
def get_products():
    if 'user_id' not in session or session['user_role'] != 'seller':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        seller_id = ObjectId(session['user_id'])
        product_list = list(products.find({"seller_id": seller_id}))
        # Convert ObjectId to string for JSON serialization
        for product in product_list:
            product['_id'] = str(product['_id'])
            product['seller_id'] = str(product['seller_id'])
        return jsonify({'success': True, 'products': product_list}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/delete-product/<product_id>', methods=['DELETE'])
def delete_product(product_id):
    if 'user_id' not in session or session['user_role'] != 'seller':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        product = products.find_one({"_id": ObjectId(product_id), "seller_id": ObjectId(session['user_id'])})
        if not product:
            return jsonify({'success': False, 'message': 'Product not found or not authorized'}), 404
        products.delete_one({"_id": ObjectId(product_id)})
        return jsonify({'success': True, 'message': 'Product deleted successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/update-product/<product_id>', methods=['PUT'])
def update_product(product_id):
    if 'user_id' not in session or session['user_role'] != 'seller':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        seller_id = ObjectId(session['user_id'])
        data = request.form
        image_file = request.files.get('image')
        update_data = {
            "name": data.get('name'),
            "category": data.get('category'),
            "price": float(data.get('price')),
            "quantity": int(data.get('quantity')),
            "unit": data.get('unit'),
            "description": data.get('description')
        }
        if image_file:
            image_data = base64.b64encode(image_file.read()).decode('utf-8')
            update_data['image_base64'] = image_data
        result = products.update_one(
            {"_id": ObjectId(product_id), "seller_id": seller_id},
            {"$set": update_data}
        )
        if result.matched_count == 0:
            return jsonify({'success': False, 'message': 'Product not found or not authorized'}), 404
        return jsonify({'success': True, 'message': 'Product updated successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/get-user-orders', methods=['GET'])
def get_user_orders():
    if 'user_id' not in session or session['user_role'] != 'user':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        user_id = ObjectId(session['user_id'])
        order_list = list(db.user_orders.find({"user_id": user_id}).sort("order_date", -1))
        return jsonify({'success': True, 'orders': dumps(order_list)}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/place-order', methods=['POST'])
def place_order():
    if 'user_id' not in session or session['user_role'] != 'user':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        data = request.get_json()
        cart = data.get('cart')
        payment_method = data.get('payment_method')
        if not cart or not payment_method:
            return jsonify({'success': False, 'message': 'Missing cart or payment method'}), 400

        # Validate cart items
        for item in cart:
            if not isinstance(item.get('price'), (int, float)) or item['price'] <= 0:
                return jsonify({'success': False, 'message': 'Invalid or missing price in cart item'}), 400
            if not isinstance(item.get('quantity'), (int, float)) or item['quantity'] <= 0:
                return jsonify({'success': False, 'message': 'Invalid or missing quantity in cart item'}), 400
            if not item.get('name'):
                return jsonify({'success': False, 'message': 'Missing name in cart item'}), 400

        total = sum(item['price'] * item['quantity'] for item in cart)
        order_data = {
            "user_id": ObjectId(session['user_id']),
            "items": cart,
            "total": total,
            "payment_method": payment_method,
            "order_date": datetime.utcnow(),
            "status": "Ordered"
        }
        user_orders.insert_one(order_data)
        return jsonify({'success': True, 'message': 'Order placed successfully'}), 201
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route("/api/products")
def get_all_products():
    all_products = list(products.find({}, {
        "name": 1,
        "price": 1,
        "category": 1,
        "quantity": 1,
        "unit": 1
    }))
    for product in all_products:
        product["_id"] = str(product["_id"])
    return jsonify(all_products)




if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')