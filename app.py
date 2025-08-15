import os
import logging
import secrets
import string
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt
from functools import wraps
from dotenv import load_dotenv
import requests
import base64
import mysql.connector
from mysql.connector import errorcode
from werkzeug.security import generate_password_hash, check_password_hash
import routeros_api

# Load environment variables from .env file for sensitive data
load_dotenv()

# --- Logging Configuration ---
# Use a custom formatter for more detailed logs
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.basicConfig(level=logging.INFO, handlers=[handler])

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for the frontend
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')

# --- M-PESA Daraja API Configuration ---
MPESA_CONSUMER_KEY = os.environ.get('MPESA_CONSUMER_KEY')
MPESA_CONSUMER_SECRET = os.environ.get('MPESA_CONSUMER_SECRET')
MPESA_BUSINESS_SHORTCODE = os.environ.get('MPESA_BUSINESS_SHORTCODE')
MPESA_PASSKEY = os.environ.get('MPESA_PASSKEY')
MPESA_CALLBACK_URL = os.environ.get('MPESA_CALLBACK_URL')
MPESA_API_BASE_URL = "https://sandbox.safaricom.co.ke"  # Use 'https://api.safaricom.co.ke' for production

# --- MySQL Database Configuration ---
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USER', 'root')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
DB_NAME = os.environ.get('DB_NAME', 'hotspot_db')


def get_db_connection():
    """
    Establishes a connection to the MySQL database.
    This version assumes the database already exists.
    """
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        logging.info("Database connection successful.")
        return conn
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            logging.error("Database connection failed: Invalid user or password.")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            # The database doesn't exist, which is handled during setup.
            logging.warning("Database does not exist. This is expected during initial setup.")
            return None
        else:
            logging.error(f"Database connection failed. Ensure MySQL is running. Error: {err}")
        return None


def create_database_if_not_exists(conn):
    """
    Creates the database if it does not already exist.
    This requires a connection to the server without a specified database.
    """
    cursor = conn.cursor()
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}`")
        logging.info(f"Database '{DB_NAME}' created or already exists.")
    except Exception as e:
        logging.error(f"Error creating database: {e}")
    finally:
        cursor.close()


def create_db_tables():
    """
    Creates the necessary tables if they don't exist.
    This version now handles creating the database first.
    """
    # First, connect to the MySQL server without specifying a database
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
        )
    except mysql.connector.Error as err:
        logging.error(f"Failed to connect to MySQL server to create database: {err}")
        return

    # Now, create the database if it doesn't exist
    create_database_if_not_exists(conn)

    # Close the server connection and open a new one to the new database
    if conn and conn.is_connected():
        conn.close()

    conn = get_db_connection()
    if conn is None:
        logging.error("Skipping table creation due to failed database connection.")
        return

    try:
        cursor = conn.cursor()
        tables = {}
        tables['users'] = (
            "CREATE TABLE `users` ("
            "  `id` int(11) NOT NULL AUTO_INCREMENT,"
            "  `mac_address` varchar(17) NOT NULL UNIQUE,"
            "  `expiry` datetime NOT NULL,"
            "  `status` varchar(20) NOT NULL,"
            "  `created_at` datetime NOT NULL,"
            "  PRIMARY KEY (`id`)"
            ") ENGINE=InnoDB")

        tables['codes'] = (
            "CREATE TABLE `codes` ("
            "  `id` int(11) NOT NULL AUTO_INCREMENT,"
            "  `code` varchar(6) NOT NULL UNIQUE,"
            "  `mac_address` varchar(17) DEFAULT NULL,"
            "  `expiry` datetime NOT NULL,"
            "  `status` varchar(20) NOT NULL,"
            "  `created_at` datetime NOT NULL,"
            "  PRIMARY KEY (`id`)"
            ") ENGINE=InnoDB")

        tables['payments'] = (
            "CREATE TABLE `payments` ("
            "  `id` int(11) NOT NULL AUTO_INCREMENT,"
            "  `transaction_id` varchar(255) NOT NULL UNIQUE,"
            "  `phone_number` varchar(15) NOT NULL,"
            "  `amount` decimal(10,2) NOT NULL,"
            "  `mac_address` varchar(17) NOT NULL,"
            "  `status` varchar(20) NOT NULL,"
            "  `created_at` datetime NOT NULL,"
            "  PRIMARY KEY (`id`)"
            ") ENGINE=InnoDB")

        # New table to store admin credentials securely with a password hash
        tables['admins'] = (
            "CREATE TABLE `admins` ("
            "  `id` INT(11) NOT NULL AUTO_INCREMENT,"
            "  `username` VARCHAR(255) NOT NULL UNIQUE,"
            "  `password_hash` VARCHAR(255) NOT NULL,"
            "  PRIMARY KEY (`id`)"
            ") ENGINE=InnoDB")

        for name, ddl in tables.items():
            try:
                logging.info(f"Creating table {name}: ", end='')
                cursor.execute(ddl)
            except mysql.connector.Error as err:
                if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                    logging.info("already exists.")
                else:
                    logging.error(f"Error creating table {name}: {err.msg}")
            else:
                logging.info("OK")
    except Exception as e:
        logging.error(f"Error creating tables: {e}")
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


def bootstrap_admin():
    """
    Creates a default admin user in the database if one doesn't exist,
    using credentials from the .env file for initial setup.
    """
    conn = get_db_connection()
    if conn is None:
        logging.error("Skipping admin bootstrap due to failed database connection.")
        return

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) FROM admins")
        if cursor.fetchone()['COUNT(*)'] == 0:
            logging.info("No admin user found. Creating initial admin.")
            admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'password')
            hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')
            sql = "INSERT INTO admins (username, password_hash) VALUES (%s, %s)"
            val = (admin_username, hashed_password)
            cursor.execute(sql, val)
            conn.commit()
            logging.info(f"Initial admin '{admin_username}' created. Password is set from .env file.")
        else:
            logging.info("Admin user already exists.")
    except Exception as e:
        logging.error(f"Error bootstrapping admin: {e}")
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


def get_mpesa_access_token():
    """Fetches the M-Pesa Daraja API access token."""
    try:
        response = requests.get(
            f"{MPESA_API_BASE_URL}/oauth/v1/generate?grant_type=client_credentials",
            auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET)
        )
        response.raise_for_status()
        access_token = response.json()['access_token']
        logging.info("Successfully fetched M-Pesa access token.")
        return access_token
    except requests.exceptions.RequestException as e:
        logging.error(f"Error getting M-Pesa access token: {e}")
        return None


# --- REAL MIKROTIK INTEGRATION ---
MIKROTIK_HOST = os.environ.get('MIKROTIK_HOST')
MIKROTIK_USERNAME = os.environ.get('MIKROTIK_USERNAME')
MIKROTIK_PASSWORD = os.environ.get('MIKROTIK_PASSWORD')


def get_mikrotik_connection():
    """Establishes a connection to the MikroTik router using routeros-api."""
    if not all([MIKROTIK_HOST, MIKROTIK_USERNAME, MIKROTIK_PASSWORD]):
        logging.warning("MikroTik credentials are not set in the .env file. Skipping connection.")
        return None
    try:
        api = routeros_api.RouterOsApiPool(
            MIKROTIK_HOST,
            username=MIKROTIK_USERNAME,
            password=MIKROTIK_PASSWORD,
            plaintext_login=True
        )
        # New debug line to show if the MikroTik connection is successful
        logging.debug("MikroTik connection successful.")
        return api
    except Exception as e:
        logging.error(f"Error connecting to MikroTik router: {e}")
        return None


def get_mac_from_ip(ip_address):
    """
    Queries MikroTik to get the MAC address associated with a given IP address.
    """
    api_pool = get_mikrotik_connection()
    if not api_pool:
        return None

    try:
        api = api_pool.get_api()
        # Find the active hotspot user with the given IP
        users = api.get_resource('/ip/hotspot/active').get(address=ip_address)
        if users:
            mac_address = users[0].get('mac-address')
            logging.info(f"Successfully fetched MAC '{mac_address}' for IP '{ip_address}' from MikroTik.")
            return mac_address
        else:
            logging.warning(f"No active MikroTik user found for IP '{ip_address}'.")
            return None
    except Exception as e:
        logging.error(f"Error fetching MAC for IP '{ip_address}' from MikroTik: {e}")
        return None
    finally:
        if api_pool:
            api_pool.disconnect()


def get_mikrotik_active_users():
    """Fetches real active users from the MikroTik hotspot."""
    api_pool = get_mikrotik_connection()
    if not api_pool:
        return []

    try:
        api = api_pool.get_api()
        users = api.get_resource('/ip/hotspot/active').get()
        formatted_users = [
            {"ip": user.get('address'), "mac_address": user.get('mac-address'), "uptime": user.get('uptime')}
            for user in users
        ]
        logging.info(f"Fetched {len(formatted_users)} active users from MikroTik.")
        return formatted_users
    except Exception as e:
        logging.error(f"Error fetching MikroTik users: {e}")
        return []
    finally:
        if api_pool:
            api_pool.disconnect()


def add_user_to_hotspot(username, password, plan_hours):
    """
    Adds or updates a user on the MikroTik hotspot with a specific time limit.
    This version now uses a username (phone number) and password (MAC address).
    """
    api_pool = get_mikrotik_connection()
    if not api_pool:
        return False

    try:
        api = api_pool.get_api()
        time_limit = f"{plan_hours}h"

        # Check if the user already exists in the MikroTik user list
        existing_users = api.get_resource('/ip/hotspot/user').get(name=username)

        if existing_users:
            user_id = existing_users[0]['.id']
            # Update the existing user with the new time limit
            api.get_resource('/ip/hotspot/user').set(
                **{'.id': user_id, 'limit-uptime': time_limit}
            )
            logging.info(f"MikroTik action: Updated user '{username}' with new time limit: {time_limit}.")
        else:
            # Add a new user
            api.get_resource('/ip/hotspot/user').add(
                **{
                    'name': username,
                    'password': password,
                    'limit-uptime': time_limit,
                    'profile': 'default'  # A default profile should be configured on the router
                }
            )
            logging.info(f"MikroTik action: Added new user '{username}' with time limit: {time_limit}.")
        return True
    except Exception as e:
        logging.error(f"Error adding or updating user on MikroTik hotspot: {e}")
        return False
    finally:
        if api_pool:
            api_pool.disconnect()


def remove_user_from_hotspot(username):
    """
    Removes a user from the MikroTik hotspot.
    This could be used for cleaning up expired accounts.
    """
    api_pool = get_mikrotik_connection()
    if not api_pool:
        return False

    try:
        api = api_pool.get_api()
        # Find the user by name
        existing_users = api.get_resource('/ip/hotspot/user').get(name=username)
        if existing_users:
            user_id = existing_users[0]['.id']
            api.get_resource('/ip/hotspot/user').remove(**{'.id': user_id})
            logging.info(f"MikroTik action: Removed user '{username}'.")
            return True
        else:
            logging.warning(f"MikroTik user '{username}' not found.")
            return False
    except Exception as e:
        logging.error(f"Error removing user from MikroTik hotspot: {e}")
        return False
    finally:
        if api_pool:
            api_pool.disconnect()


def generate_alphanumeric_code():
    """Generates a random 6-character alphanumeric code."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(6))


# --- Admin Authentication Decorator ---
def token_required(f):
    """Decorator to protect admin routes."""

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            logging.warning("Admin access denied: Token is missing from request headers.")
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            logging.info(f"Admin '{data.get('user')}' authenticated via token.")
        except Exception as e:
            logging.error(f"Admin access denied: Token is invalid. Error: {e}")
            return jsonify({'message': f'Token is invalid! {e}'}), 401

        return f(data, *args, **kwargs)

    return decorated


# --- Public API Endpoints ---

@app.route('/')
def serve_index():
    """Serves the main HTML landing page."""
    return render_template('index.html')


@app.route('/api/check_mac_subscription', methods=['POST'])
def check_mac_subscription():
    """
    Checks if a given MAC address has an active subscription.
    It now checks for a database connection first.
    """
    data = request.get_json()
    # The client now sends the IP address
    ip_address = data.get('ip_address')
    logging.info(f"Request to check subscription for IP: {ip_address}")

    if not ip_address:
        return jsonify({'success': False, 'message': 'IP address is required'}), 400

    # Step 1: ALWAYS get the MAC address from MikroTik first.
    mac_address = get_mac_from_ip(ip_address)
    if not mac_address:
        return jsonify(
            {'success': False, 'message': 'Could not get MAC address from MikroTik. Are you connected?'}), 400

    # Step 2: Now, try to connect to the database. If it fails, stop.
    conn = get_db_connection()
    if conn is None:
        # If database connection fails, provide a clear error message.
        return jsonify({
            'success': False,
            'is_subscribed': False,
            'message': 'Subscription check is temporarily unavailable due to a database error.'
        }), 503  # 503 Service Unavailable

    try:
        cursor = conn.cursor(dictionary=True)
        # Refined query: only select the columns you need for efficiency
        query = "SELECT expiry FROM users WHERE mac_address = %s AND status = 'active' AND expiry > %s"
        cursor.execute(query, (mac_address, datetime.now()))
        user = cursor.fetchone()

        if user:
            logging.info(f"Active subscription found for MAC: {mac_address}, expiring at {user['expiry']}")
            return jsonify({
                'success': True,
                'is_subscribed': True,
                'mac_address': mac_address,
                'expiry': user['expiry'].isoformat()
            })

        logging.info(f"No active subscription found for MAC: {mac_address}")
        return jsonify({'success': True, 'is_subscribed': False, 'mac_address': mac_address})
    except Exception as e:
        logging.error(f"Error checking subscription for MAC {mac_address}: {e}")
        return jsonify({'success': False, 'message': 'An error occurred.'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/api/initiate_payment', methods=['POST'])
def initiate_payment():
    """
    Initiates a real M-Pesa STK push.
    It now requires a MAC address and checks the database connection first.
    """
    data = request.get_json()
    phone_number = data.get('phone_number')
    amount = data.get('amount')
    mac_address = data.get('mac_address')  # MAC address is now required directly
    logging.info(f"Request to initiate payment for phone: {phone_number}, amount: {amount}, mac: {mac_address}")

    if not all([phone_number, amount, mac_address]):
        logging.warning("Missing data for payment initiation.")
        return jsonify({'success': False, 'message': 'Missing data'}), 400

    # Step 1: Connect to the database. If it fails, stop all processes.
    conn = get_db_connection()
    if conn is None:
        logging.error("Database connection failed. Cannot proceed with payment.")
        return jsonify({
            'success': False,
            'message': 'Cannot process payment at this time. Please try again later.'
        }), 503  # 503 Service Unavailable

    try:
        cursor = conn.cursor(dictionary=True)
        # Check for an existing active subscription before payment
        query = "SELECT id FROM users WHERE mac_address = %s AND status = 'active' AND expiry > %s"
        cursor.execute(query, (mac_address, datetime.now()))
        if cursor.fetchone():
            logging.info(f"User with MAC {mac_address} already has an active subscription. Denying new purchase.")
            return jsonify({'success': False, 'message': 'You already have an active subscription.'}), 409
    except Exception as e:
        logging.error(f"Error checking for existing subscription: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while checking subscription status.'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

    if not all(
            [MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET, MPESA_BUSINESS_SHORTCODE, MPESA_PASSKEY, MPESA_CALLBACK_URL]):
        logging.error("M-Pesa API credentials are not set in the .env file.")
        return jsonify({'success': False, 'message': 'M-Pesa API credentials are not set in the .env file.'}), 500

    access_token = get_mpesa_access_token()
    if not access_token:
        return jsonify({'success': False, 'message': 'Failed to get M-Pesa access token.'}), 500

    if phone_number.startswith('0'):
        phone_number = '254' + phone_number[1:]

    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode(f"{MPESA_BUSINESS_SHORTCODE}{MPESA_PASSKEY}{timestamp}".encode('utf-8')).decode('utf-8')

    stk_push_data = {
        "BusinessShortCode": MPESA_BUSINESS_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone_number,
        "PartyB": MPESA_BUSINESS_SHORTCODE,
        "PhoneNumber": phone_number,
        "CallBackURL": MPESA_CALLBACK_URL,
        "AccountReference": "Hotspot Subscription",
        "TransactionDesc": f"Payment for {amount_to_hours(amount)} hour hotspot access"
    }

    logging.info(f"M-Pesa STK Push Request Payload: {stk_push_data}")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            f"{MPESA_API_BASE_URL}/mpesa/stkpush/v1/processrequest",
            json=stk_push_data,
            headers=headers
        )
        response.raise_for_status()

        response_json = response.json()
        logging.info(f"M-Pesa STK Push Response: {response_json}")
        if 'CheckoutRequestID' in response_json:
            conn = get_db_connection()
            if conn is not None:
                try:
                    cursor = conn.cursor()
                    sql = "INSERT INTO payments (transaction_id, phone_number, amount, mac_address, status, created_at) VALUES (%s, %s, %s, %s, %s, %s)"
                    val = (response_json['CheckoutRequestID'], phone_number, amount, mac_address, 'pending',
                           datetime.now())
                    cursor.execute(sql, val)
                    conn.commit()
                    logging.info(
                        f"Payment initiated and saved to DB with CheckoutRequestID: {response_json['CheckoutRequestID']} for MAC: {mac_address}")
                except Exception as e:
                    logging.error(f"Error saving payment to DB: {e}")
                finally:
                    if conn and conn.is_connected():
                        cursor.close()
                        conn.close()

            return jsonify({
                'success': True,
                'message': 'Payment prompt sent. Please check your phone.',
                'transaction_id': response_json['CheckoutRequestID']
            })
        else:
            logging.error(f"M-Pesa API responded with an error: {response_json}")
            return jsonify(
                {'success': False, 'message': response_json.get('CustomerMessage', 'An error occurred.')}), 400
    except requests.exceptions.RequestException as e:
        logging.error(f"Error initiating M-Pesa STK push: {e}")
        if e.response:
            logging.error(f"M-Pesa API Response: {e.response.text}")
        return jsonify({'success': False, 'message': 'Failed to connect to M-Pesa API.'}), 500


@app.route('/api/mpesa_callback', methods=['POST'])
def mpesa_callback():
    """
    Endpoint that receives the callback from the M-Pesa API.
    This is where we process the payment status and activate the hotspot.
    """
    data = request.get_json()
    logging.info(f"Received M-Pesa callback: {data}")

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if conn is None:
            logging.error("Failed to connect to DB for M-Pesa callback. Cannot process transaction.")
            return jsonify({'message': 'Database connection failed'}), 500

        cursor = conn.cursor(dictionary=True)

        result_code = data['Body']['stkCallback']['ResultCode']
        checkout_request_id = data['Body']['stkCallback']['CheckoutRequestID']

        # Optimized query to get only the necessary payment info
        cursor.execute("SELECT amount, mac_address, phone_number FROM payments WHERE transaction_id = %s",
                       (checkout_request_id,))
        payment = cursor.fetchone()

        if not payment:
            logging.error(f"Callback error: Payment with transaction_id {checkout_request_id} not found in database.")
            return jsonify({'message': 'Payment not found'}), 404

        if result_code == 0:
            payment_status = 'paid'
            mac_address = payment['mac_address']
            phone_number = payment['phone_number']
            amount = payment['amount']
            plan_hours = amount_to_hours(amount)
            expiry_time = datetime.now() + timedelta(hours=plan_hours)

            # Update payment status
            logging.info(f"Payment successful. Updating payment status for CheckoutRequestID: {checkout_request_id}")
            cursor.execute("UPDATE payments SET status = %s WHERE transaction_id = %s",
                           (payment_status, checkout_request_id))

            # Check if user exists (to prevent creating a new row for an expired sub)
            cursor.execute("SELECT id FROM users WHERE mac_address = %s", (mac_address,))
            existing_user = cursor.fetchone()

            if existing_user:
                # Update expiry for existing user
                cursor.execute("UPDATE users SET expiry = %s, status = 'active' WHERE mac_address = %s",
                               (expiry_time, mac_address))
            else:
                # Create a new user account
                logging.info(f"New user. Creating hotspot account for MAC: {mac_address}.")
                sql = "INSERT INTO users (mac_address, expiry, status, created_at) VALUES (%s, %s, %s, %s)"
                val = (mac_address, expiry_time, 'active', datetime.now())
                cursor.execute(sql, val)

            conn.commit()

            if add_user_to_hotspot(phone_number, mac_address, plan_hours):
                logging.info(
                    f"Payment successful for MAC: {mac_address}. Hotspot account created and MikroTik updated.")
            else:
                logging.warning(
                    f"Payment successful for MAC: {mac_address}, but an error occurred while adding to MikroTik.")
        else:
            payment_status = 'failed'
            logging.warning(f"Payment failed for CheckoutRequestID: {checkout_request_id}. ResultCode: {result_code}")
            cursor.execute("UPDATE payments SET status = %s WHERE transaction_id = %s",
                           (payment_status, checkout_request_id))
            conn.commit()
            logging.info("Payment status updated to 'failed'.")
    except KeyError as e:
        logging.error(f"M-Pesa callback payload has a missing key: {e}")
        if conn and conn.is_connected():
            conn.rollback()
        return jsonify({'message': 'Invalid payload format'}), 400
    except Exception as e:
        logging.error(f"Error in mpesa_callback: {e}")
        if conn and conn.is_connected():
            conn.rollback()
        return jsonify({'message': 'An internal error occurred'}), 500
    finally:
        if conn and conn.is_connected():
            if cursor:
                cursor.close()
            conn.close()

    return jsonify({'message': 'Callback received successfully'}), 200


@app.route('/api/connect_with_code', methods=['POST'])
def connect_with_code():
    """
    Connects a user to the hotspot using a pre-generated 6-digit code.
    This endpoint now gets the MAC address from MikroTik using the client's IP.
    """
    data = request.get_json()
    code = data.get('code')
    ip_address = data.get('ip_address')
    logging.info(f"Request to connect with code '{code}' for IP: {ip_address}")

    if not all([code, ip_address]):
        logging.warning("Missing data for code connection.")
        return jsonify({'success': False, 'message': 'Missing code or IP address'}), 400

    # Get the MAC address from MikroTik based on the IP
    mac_address = get_mac_from_ip(ip_address)
    if not mac_address:
        return jsonify(
            {'success': False, 'message': 'Could not get MAC address from MikroTik. Are you connected?'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'success': False, 'message': 'Database connection failed.'}), 500

    try:
        cursor = conn.cursor(dictionary=True)
        # Refined query: only get what you need
        cursor.execute("SELECT expiry, mac_address FROM codes WHERE code = %s", (code,))
        account = cursor.fetchone()

        if not account:
            logging.warning(f"Invalid code '{code}' provided.")
            return jsonify({'success': False, 'message': 'Invalid code provided.'})

        if account.get('mac_address') and account.get('mac_address') != mac_address:
            logging.warning(f"Code '{code}' already in use by a different MAC address.")
            return jsonify({'success': False, 'message': 'This code is already in use.'})

        if account.get('expiry') and account['expiry'] < datetime.now():
            logging.warning(f"Code '{code}' has expired.")
            return jsonify({'success': False, 'message': 'This code has expired.'})

        # Update the code to be used
        logging.info(f"Code '{code}' is valid. Activating for MAC: {mac_address}")
        cursor.execute("UPDATE codes SET mac_address = %s, status = 'active' WHERE code = %s", (mac_address, code))

        # Create a new user account entry
        time_left = (account['expiry'] - datetime.now()).total_seconds() / 3600
        sql = "INSERT INTO users (mac_address, expiry, status, created_at) VALUES (%s, %s, %s, %s)"
        val = (mac_address, account['expiry'], 'active', datetime.now())
        cursor.execute(sql, val)
        conn.commit()

        if add_user_to_hotspot(code, mac_address, time_left):
            logging.info(f"Successfully connected MAC: {mac_address} with code '{code}'.")
            return jsonify({
                'success': True,
                'message': f'Welcome! You are now connected with code {code}.'
            })
        else:
            logging.error(f"Failed to connect to MikroTik with code '{code}'.")
            return jsonify({'success': False, 'message': 'Failed to connect to the hotspot.'})
    except Exception as e:
        logging.error(f"Error connecting with code '{code}': {e}")
        if conn and conn.is_connected():
            conn.rollback()
        return jsonify({'success': False, 'message': 'An error occurred.'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


# --- Admin API Endpoints ---

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Authenticates the admin and issues a JWT token."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    logging.info(f"Attempting admin login for user: {username}")

    if not all([username, password]):
        logging.warning("Admin login failed: Missing username or password.")
        return jsonify({'success': False, 'message': 'Username and password are required.'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'success': False, 'message': 'Database connection failed.'}), 500

    try:
        cursor = conn.cursor(dictionary=True)
        # Refined query to get only the password hash
        cursor.execute("SELECT password_hash FROM admins WHERE username = %s", (username,))
        admin_user = cursor.fetchone()

        if admin_user and check_password_hash(admin_user['password_hash'], password):
            token = jwt.encode({
                'user': username,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            logging.info(f"Admin '{username}' successfully logged in.")
            return jsonify({'success': True, 'token': token})
        else:
            logging.warning(f"Admin login failed for user: {username}. Invalid credentials.")
    except Exception as e:
        logging.error(f"Error during admin login for user {username}: {e}")
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401


@app.route('/api/admin/update_credentials', methods=['POST'])
@token_required
def update_credentials(current_user):
    """Allows an authenticated admin to change their username and password."""
    data = request.get_json()
    new_username = data.get('username')
    new_password = data.get('password')
    logging.info(f"Admin '{current_user['user']}' attempting to update credentials.")

    if not all([new_username, new_password]):
        logging.warning("Credential update failed: Missing new username or password.")
        return jsonify({'success': False, 'message': 'New username and password are required.'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'success': False, 'message': 'Database connection failed.'}), 500

    try:
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        cursor = conn.cursor()
        cursor.execute("UPDATE admins SET username = %s, password_hash = %s WHERE username = %s",
                       (new_username, hashed_password, current_user['user']))
        conn.commit()
        logging.info(f"Admin '{current_user['user']}' successfully updated credentials to '{new_username}'.")
        return jsonify(
            {'success': True, 'message': 'Credentials updated successfully. Please log in with the new credentials.'})
    except Exception as e:
        logging.error(f"Error updating credentials for admin '{current_user['user']}': {e}")
        conn.rollback()
        return jsonify({'success': False, 'message': 'Failed to update credentials.'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/api/admin/change_password', methods=['POST'])
@token_required
def change_password(current_user):
    """Allows an authenticated admin to change their password."""
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    logging.info(f"Admin '{current_user['user']}' attempting to change password.")

    if not all([old_password, new_password]):
        logging.warning("Password change failed: Missing old or new password.")
        return jsonify({'success': False, 'message': 'Both old and new password are required.'}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'success': False, 'message': 'Database connection failed.'}), 500

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT password_hash FROM admins WHERE username = %s", (current_user['user'],))
        admin_user = cursor.fetchone()

        if not admin_user or not check_password_hash(admin_user['password_hash'], old_password):
            logging.warning(f"Admin '{current_user['user']}' failed to change password due to invalid old password.")
            return jsonify({'success': False, 'message': 'Invalid old password.'}), 401

        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        cursor.execute("UPDATE admins SET password_hash = %s WHERE username = %s",
                       (hashed_password, current_user['user']))
        conn.commit()
        logging.info(f"Admin '{current_user['user']}' successfully changed their password.")
        return jsonify({'success': True, 'message': 'Password changed successfully.'})
    except Exception as e:
        logging.error(f"Error changing password for admin '{current_user['user']}': {e}")
        conn.rollback()
        return jsonify({'success': False, 'message': 'Failed to change password.'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


@app.route('/api/admin/get_mikrotik_users', methods=['GET'])
@token_required
def get_mikrotik_users_endpoint(current_user):
    """Fetches the list of active users from the MikroTik router."""
    logging.info(f"Admin '{current_user['user']}' requested active MikroTik users.")
    users = get_mikrotik_active_users()
    return jsonify({'success': True, 'users': users})


@app.route('/api/admin/create_hotspot_code', methods=['POST'])
@token_required
def create_hotspot_code(current_user):
    """
    Creates a new hotspot account with a unique 6-digit alphanumeric code.
    This can be used for manual connection.
    """
    data = request.get_json()
    mac_address = data.get('mac_address')
    expiry_days = data.get('expiry_days', 7)
    logging.info(f"Admin '{current_user['user']}' is creating a new hotspot code with expiry of {expiry_days} days.")

    conn = get_db_connection()
    if conn is None:
        return jsonify({'success': False, 'message': 'Database connection failed.'}), 500

    try:
        cursor = conn.cursor()
        code = generate_alphanumeric_code()
        # Check for uniqueness and regenerate if needed
        cursor.execute("SELECT COUNT(*) FROM codes WHERE code = %s", (code,))
        while cursor.fetchone()[0] > 0:
            logging.warning(f"Generated code '{code}' already exists. Regenerating.")
            code = generate_alphanumeric_code()
            cursor.execute("SELECT COUNT(*) FROM codes WHERE code = %s", (code,))

        sql = "INSERT INTO codes (code, mac_address, expiry, status, created_at) VALUES (%s, %s, %s, %s, %s, %s)"
        val = (code, mac_address, datetime.now() + timedelta(days=expiry_days), 'pending', datetime.now())
        cursor.execute(sql, val)
        conn.commit()
        logging.info(f"Admin '{current_user['user']}' successfully created code: {code}.")

        return jsonify({
            'success': True,
            'message': f'Account created with code: {code}.',
            'code': code
        })
    except Exception as e:
        logging.error(f"Error creating hotspot code: {e}")
        conn.rollback()
        return jsonify({'success': False, 'message': 'An error occurred.'}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


# --- Helper Functions ---
def amount_to_hours(amount):
    """Maps payment amounts to hours of access."""
    amount = int(amount)
    if amount == 10: return 1
    if amount == 20: return 6
    if amount == 30: return 12
    if amount == 50: return 24
    if amount == 70: return 48
    if amount == 300: return 168
    return 0


if __name__ == '__main__':
    # You should run this once to set up your tables and admin
    create_db_tables()
    bootstrap_admin()
    app.run(debug=True, port=5000)

