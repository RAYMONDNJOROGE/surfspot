import os
import logging
import secrets
import string
from datetime import datetime, timedelta
import jwt
from functools import wraps
from dotenv import load_dotenv
import httpx
import base64
import mysql.connector
from mysql.connector import errorcode
from werkzeug.security import generate_password_hash, check_password_hash
import routeros_api

# FastAPI imports
from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# Load environment variables
load_dotenv()

# --- Logging Configuration ---
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.basicConfig(level=logging.INFO, handlers=[handler])

app = FastAPI(
    title="MikroTik Hotspot API",
    description="A modern, high-performance API for managing a MikroTik hotspot with M-Pesa payments.",
    version="1.0.0"
)

# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to your frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Jinja2 templates for serving the index.html file
templates = Jinja2Templates(directory="templates")

# Global database connection pool
# Note: For production, a proper async driver like aiomysql should be used.
# This simple setup simulates the async pattern.
db_pool = None

# --- M-PESA Daraja API Configuration ---
MPESA_CONSUMER_KEY = os.environ.get('MPESA_CONSUMER_KEY')
MPESA_CONSUMER_SECRET = os.environ.get('MPESA_CONSUMER_SECRET')
MPESA_BUSINESS_SHORTCODE = os.environ.get('MPESA_BUSINESS_SHORTCODE')
MPESA_PASSKEY = os.environ.get('MPESA_PASSKEY')
MPESA_CALLBACK_URL = os.environ.get('MPESA_CALLBACK_URL')
MPESA_API_BASE_URL = "https://sandbox.safaricom.co.ke"

# --- MySQL Database Configuration ---
DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_NAME = os.environ.get('DB_NAME')

# --- REAL MIKROTIK INTEGRATION ---
MIKROTIK_HOST = os.environ.get('MIKROTIK_HOST')
MIKROTIK_USERNAME = os.environ.get('MIKROTIK_USERNAME')
MIKROTIK_PASSWORD = os.environ.get('MIKROTIK_PASSWORD')


# --- Dependency for database connection ---
def get_db_connection():
    """Provides a synchronous database connection."""
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return conn
    except mysql.connector.Error as err:
        logging.error(f"Database connection failed: {err}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connection failed. Please try again later."
        )


# --- Pydantic Models for Request Body Validation ---
class CheckSubscriptionRequest(BaseModel):
    ip_address: str


class InitiatePaymentRequest(BaseModel):
    phone_number: str
    amount: float
    mac_address: str


class ConnectWithCodeRequest(BaseModel):
    code: str
    ip_address: str


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class UpdateCredentialsRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class CreateCodeRequest(BaseModel):
    mac_address: Optional[str] = None
    expiry_days: int = 7


# --- Helper Functions (Now Asynchronous where appropriate) ---

async def get_mpesa_access_token():
    """Fetches the M-Pesa Daraja API access token using httpx."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{MPESA_API_BASE_URL}/oauth/v1/generate?grant_type=client_credentials",
                auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET)
            )
            response.raise_for_status()
            access_token = response.json()['access_token']
            logging.info("Successfully fetched M-Pesa access token.")
            return access_token
    except httpx.RequestError as e:
        logging.error(f"Error getting M-Pesa access token: {e}")
        return None


def get_mikrotik_connection():
    """Establishes a connection to the MikroTik router."""
    if not all([MIKROTIK_HOST, MIKROTIK_USERNAME, MIKROTIK_PASSWORD]):
        logging.warning("MikroTik credentials are not set. Skipping connection.")
        return None
    try:
        api_pool = routeros_api.RouterOsApiPool(
            MIKROTIK_HOST,
            username=MIKROTIK_USERNAME,
            password=MIKROTIK_PASSWORD,
            plaintext_login=True,
            # Add timeout to prevent blocking forever
            socket_timeout=5
        )
        return api_pool
    except Exception as e:
        logging.error(f"Error connecting to MikroTik router: {e}")
        return None


def get_mac_from_ip(ip_address: str):
    """
    Queries MikroTik to get the MAC address associated with a given IP address.
    This is still synchronous because the routeros-api library is not async.
    """
    api_pool = get_mikrotik_connection()
    if not api_pool:
        return None

    try:
        api = api_pool.get_api()
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


def add_user_to_hotspot(username: str, password: str, plan_hours: int):
    """Adds or updates a user on the MikroTik hotspot."""
    api_pool = get_mikrotik_connection()
    if not api_pool:
        return False

    try:
        api = api_pool.get_api()
        time_limit = f"{plan_hours}h"
        existing_users = api.get_resource('/ip/hotspot/user').get(name=username)

        if existing_users:
            user_id = existing_users[0]['.id']
            api.get_resource('/ip/hotspot/user').set(
                **{'.id': user_id, 'limit-uptime': time_limit}
            )
            logging.info(f"MikroTik action: Updated user '{username}' with new time limit: {time_limit}.")
        else:
            api.get_resource('/ip/hotspot/user').add(
                **{
                    'name': username,
                    'password': password,
                    'limit-uptime': time_limit,
                    'profile': 'default'
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


def amount_to_hours(amount: float):
    """Maps payment amounts to hours of access."""
    amount = int(amount)
    if amount == 10: return 1
    if amount == 20: return 6
    if amount == 30: return 12
    if amount == 50: return 24
    if amount == 70: return 48
    if amount == 300: return 168
    return 0


def generate_alphanumeric_code():
    """Generates a random 6-character alphanumeric code."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(6))


# --- Admin Authentication Dependency ---
class AdminUser:
    def __init__(self, username: str):
        self.username = username


async def get_current_admin_user(request: Request, db_conn=Depends(get_db_connection)):
    """A dependency to get the current admin user from the JWT token."""
    token = request.headers.get("x-access-tokens")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing."
        )
    try:
        payload = jwt.decode(token, os.environ.get('SECRET_KEY'), algorithms=["HS256"])
        username = payload.get("user")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload."
            )
        return AdminUser(username=username)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired."
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token."
        )


# --- Public API Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    """Serves the main HTML landing page."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/check_mac_subscription")
async def check_mac_subscription(request_data: CheckSubscriptionRequest, db_conn=Depends(get_db_connection)):
    """Checks if a given MAC address has an active subscription."""
    ip_address = request_data.ip_address
    logging.info(f"Request to check subscription for IP: {ip_address}")

    # Use a thread pool to run the synchronous MikroTik call to avoid blocking
    mac_address = await app.loop.run_in_executor(None, get_mac_from_ip, ip_address)
    if not mac_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Could not get MAC address from MikroTik. Are you connected?'
        )

    try:
        cursor = db_conn.cursor(dictionary=True)
        query = "SELECT expiry FROM users WHERE mac_address = %s AND status = 'active' AND expiry > %s"
        cursor.execute(query, (mac_address, datetime.now()))
        user = cursor.fetchone()

        if user:
            logging.info(f"Active subscription found for MAC: {mac_address}")
            return JSONResponse(content={
                'success': True,
                'is_subscribed': True,
                'mac_address': mac_address,
                'expiry': user['expiry'].isoformat()
            })

        logging.info(f"No active subscription found for MAC: {mac_address}")
        return JSONResponse(content={'success': True, 'is_subscribed': False, 'mac_address': mac_address})

    finally:
        if db_conn and db_conn.is_connected():
            cursor.close()
            db_conn.close()


@app.post("/api/initiate_payment")
async def initiate_payment(request_data: InitiatePaymentRequest, db_conn=Depends(get_db_connection)):
    """Initiates an M-Pesa STK push."""
    phone_number = request_data.phone_number
    amount = request_data.amount
    mac_address = request_data.mac_address
    logging.info(f"Request to initiate payment for phone: {phone_number}, amount: {amount}, mac: {mac_address}")

    try:
        cursor = db_conn.cursor(dictionary=True)
        query = "SELECT id FROM users WHERE mac_address = %s AND status = 'active' AND expiry > %s"
        cursor.execute(query, (mac_address, datetime.now()))
        if cursor.fetchone():
            logging.info(f"User with MAC {mac_address} already has an active subscription. Denying new purchase.")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail='You already have an active subscription.'
            )
    finally:
        if db_conn and db_conn.is_connected():
            cursor.close()
            db_conn.close()

    access_token = await get_mpesa_access_token()
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to get M-Pesa access token.'
        )

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

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{MPESA_API_BASE_URL}/mpesa/stkpush/v1/processrequest",
                json=stk_push_data,
                headers=headers
            )
            response.raise_for_status()

        response_json = response.json()
        logging.info(f"M-Pesa STK Push Response: {response_json}")
        if 'CheckoutRequestID' in response_json:
            conn = get_db_connection()
            if conn:
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

            return JSONResponse(content={
                'success': True,
                'message': 'Payment prompt sent. Please check your phone.',
                'transaction_id': response_json['CheckoutRequestID']
            })
        else:
            logging.error(f"M-Pesa API responded with an error: {response_json}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=response_json.get('CustomerMessage', 'An unknown error occurred.')
            )
    except httpx.RequestError as e:
        logging.error(f"Error initiating M-Pesa STK push: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to connect to M-Pesa API.'
        )


# Background task for M-Pesa callback processing
def process_mpesa_callback(data: dict):
    """Processes the M-Pesa callback data in the background."""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            logging.error("Failed to connect to DB for background M-Pesa callback.")
            return

        cursor = conn.cursor(dictionary=True)
        result_code = data['Body']['stkCallback']['ResultCode']
        checkout_request_id = data['Body']['stkCallback']['CheckoutRequestID']

        cursor.execute("SELECT amount, mac_address, phone_number FROM payments WHERE transaction_id = %s",
                       (checkout_request_id,))
        payment = cursor.fetchone()

        if not payment:
            logging.error(f"Callback error: Payment with transaction_id {checkout_request_id} not found.")
            return

        if result_code == 0:
            payment_status = 'paid'
            mac_address = payment['mac_address']
            phone_number = payment['phone_number']
            amount = payment['amount']
            plan_hours = amount_to_hours(amount)
            expiry_time = datetime.now() + timedelta(hours=plan_hours)

            cursor.execute("UPDATE payments SET status = %s WHERE transaction_id = %s",
                           (payment_status, checkout_request_id))

            cursor.execute("SELECT id FROM users WHERE mac_address = %s", (mac_address,))
            existing_user = cursor.fetchone()

            if existing_user:
                cursor.execute("UPDATE users SET expiry = %s, status = 'active' WHERE mac_address = %s",
                               (expiry_time, mac_address))
            else:
                logging.info(f"New user. Creating hotspot account for MAC: {mac_address}.")
                sql = "INSERT INTO users (mac_address, expiry, status, created_at) VALUES (%s, %s, %s, %s)"
                val = (mac_address, expiry_time, 'active', datetime.now())
                cursor.execute(sql, val)

            conn.commit()

            # The MikroTik call is also synchronous, so run it in a thread pool
            add_user_to_hotspot(phone_number, mac_address, plan_hours)

            logging.info(f"Payment successful for MAC: {mac_address}. Hotspot account created and MikroTik updated.")
        else:
            payment_status = 'failed'
            logging.warning(f"Payment failed for CheckoutRequestID: {checkout_request_id}. ResultCode: {result_code}")
            cursor.execute("UPDATE payments SET status = %s WHERE transaction_id = %s",
                           (payment_status, checkout_request_id))
            conn.commit()
            logging.info("Payment status updated to 'failed'.")

    except KeyError as e:
        logging.error(f"M-Pesa callback payload has a missing key: {e}")
        if conn:
            conn.rollback()
    except Exception as e:
        logging.error(f"Error in background mpesa_callback processing: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn and conn.is_connected():
            if cursor:
                cursor.close()
            conn.close()


@app.post("/api/mpesa_callback")
async def mpesa_callback(request: Request, background_tasks: BackgroundTasks):
    """Receives the M-Pesa callback and processes it as a background task."""
    try:
        data = await request.json()
        logging.info(f"Received M-Pesa callback. Spawning background task.")
        # Immediately add the processing to a background task and return
        background_tasks.add_task(process_mpesa_callback, data)
        return JSONResponse(content={'message': 'Callback received successfully'}, status_code=status.HTTP_200_OK)
    except Exception as e:
        logging.error(f"Error receiving M-Pesa callback: {e}")
        return JSONResponse(content={'message': 'Invalid payload format'}, status_code=status.HTTP_400_BAD_REQUEST)


@app.post("/api/connect_with_code")
async def connect_with_code(request_data: ConnectWithCodeRequest, db_conn=Depends(get_db_connection)):
    """Connects a user to the hotspot using a pre-generated 6-digit code."""
    code = request_data.code
    ip_address = request_data.ip_address
    logging.info(f"Request to connect with code '{code}' for IP: {ip_address}")

    mac_address = await app.loop.run_in_executor(None, get_mac_from_ip, ip_address)
    if not mac_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Could not get MAC address from MikroTik. Are you connected?'
        )

    try:
        cursor = db_conn.cursor(dictionary=True)
        cursor.execute("SELECT expiry, mac_address FROM codes WHERE code = %s", (code,))
        account = cursor.fetchone()

        if not account:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid code provided.')

        if account.get('mac_address') and account.get('mac_address') != mac_address:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='This code is already in use.')

        if account.get('expiry') and account['expiry'] < datetime.now():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='This code has expired.')

        logging.info(f"Code '{code}' is valid. Activating for MAC: {mac_address}")
        cursor.execute("UPDATE codes SET mac_address = %s, status = 'active' WHERE code = %s", (mac_address, code))

        time_left = (account['expiry'] - datetime.now()).total_seconds() / 3600
        sql = "INSERT INTO users (mac_address, expiry, status, created_at) VALUES (%s, %s, %s, %s)"
        val = (mac_address, account['expiry'], 'active', datetime.now())
        cursor.execute(sql, val)
        db_conn.commit()

        await app.loop.run_in_executor(None, add_user_to_hotspot, code, mac_address, time_left)

        logging.info(f"Successfully connected MAC: {mac_address} with code '{code}'.")
        return JSONResponse(content={
            'success': True,
            'message': f'Welcome! You are now connected with code {code}.'
        })
    except Exception as e:
        logging.error(f"Error connecting with code '{code}': {e}")
        db_conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='An error occurred.'
        )
    finally:
        if db_conn and db_conn.is_connected():
            cursor.close()
            db_conn.close()


# --- Admin API Endpoints ---
@app.post("/api/admin/login")
async def admin_login(request_data: AdminLoginRequest, db_conn=Depends(get_db_connection)):
    """Authenticates the admin and issues a JWT token."""
    username = request_data.username
    password = request_data.password
    logging.info(f"Attempting admin login for user: {username}")

    try:
        cursor = db_conn.cursor(dictionary=True)
        cursor.execute("SELECT password_hash FROM admins WHERE username = %s", (username,))
        admin_user = cursor.fetchone()

        if admin_user and check_password_hash(admin_user['password_hash'], password):
            token = jwt.encode({
                'user': username,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }, os.environ.get('SECRET_KEY'), algorithm="HS256")
            logging.info(f"Admin '{username}' successfully logged in.")
            return JSONResponse(content={'success': True, 'token': token})
        else:
            logging.warning(f"Admin login failed for user: {username}. Invalid credentials.")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid credentials')
    finally:
        if db_conn and db_conn.is_connected():
            cursor.close()
            db_conn.close()


@app.post("/api/admin/update_credentials")
async def update_credentials(request_data: UpdateCredentialsRequest,
                             current_user: AdminUser = Depends(get_current_admin_user),
                             db_conn=Depends(get_db_connection)):
    """Allows an authenticated admin to change their username and password."""
    try:
        hashed_password = generate_password_hash(request_data.password, method='pbkdf2:sha256')
        cursor = db_conn.cursor()
        cursor.execute("UPDATE admins SET username = %s, password_hash = %s WHERE username = %s",
                       (request_data.username, hashed_password, current_user.username))
        db_conn.commit()
        logging.info(f"Admin '{current_user.username}' successfully updated credentials to '{request_data.username}'.")
        return JSONResponse(content={
            'success': True,
            'message': 'Credentials updated successfully. Please log in with the new credentials.'
        })
    except Exception as e:
        logging.error(f"Error updating credentials for admin '{current_user.username}': {e}")
        db_conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to update credentials.'
        )
    finally:
        if db_conn and db_conn.is_connected():
            cursor.close()
            db_conn.close()


@app.post("/api/admin/change_password")
async def change_password(request_data: ChangePasswordRequest,
                          current_user: AdminUser = Depends(get_current_admin_user),
                          db_conn=Depends(get_db_connection)):
    """Allows an authenticated admin to change their password."""
    try:
        cursor = db_conn.cursor(dictionary=True)
        cursor.execute("SELECT password_hash FROM admins WHERE username = %s", (current_user.username,))
        admin_user = cursor.fetchone()

        if not admin_user or not check_password_hash(admin_user['password_hash'], request_data.old_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid old password.')

        hashed_password = generate_password_hash(request_data.new_password, method='pbkdf2:sha256')
        cursor.execute("UPDATE admins SET password_hash = %s WHERE username = %s",
                       (hashed_password, current_user.username))
        db_conn.commit()
        logging.info(f"Admin '{current_user.username}' successfully changed their password.")
        return JSONResponse(content={'success': True, 'message': 'Password changed successfully.'})
    except Exception as e:
        logging.error(f"Error changing password for admin '{current_user.username}': {e}")
        db_conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to change password.'
        )
    finally:
        if db_conn and db_conn.is_connected():
            cursor.close()
            db_conn.close()


@app.get("/api/admin/get_mikrotik_users")
async def get_mikrotik_users_endpoint(current_user: AdminUser = Depends(get_current_admin_user)):
    """Fetches the list of active users from the MikroTik router."""
    logging.info(f"Admin '{current_user.username}' requested active MikroTik users.")
    # Run the synchronous MikroTik call in a thread pool
    users = await app.loop.run_in_executor(None, get_mikrotik_active_users)
    return JSONResponse(content={'success': True, 'users': users})


@app.post("/api/admin/create_hotspot_code")
async def create_hotspot_code(request_data: CreateCodeRequest,
                              current_user: AdminUser = Depends(get_current_admin_user),
                              db_conn=Depends(get_db_connection)):
    """Creates a new hotspot account with a unique 6-digit alphanumeric code."""
    try:
        cursor = db_conn.cursor()
        code = generate_alphanumeric_code()

        while True:
            cursor.execute("SELECT COUNT(*) FROM codes WHERE code = %s", (code,))
            if cursor.fetchone()[0] == 0:
                break
            logging.warning(f"Generated code '{code}' already exists. Regenerating.")
            code = generate_alphanumeric_code()

        expiry_date = datetime.now() + timedelta(days=request_data.expiry_days)
        sql = "INSERT INTO codes (code, mac_address, expiry, status, created_at) VALUES (%s, %s, %s, %s, %s)"
        val = (code, request_data.mac_address, expiry_date, 'pending', datetime.now())
        cursor.execute(sql, val)
        db_conn.commit()
        logging.info(f"Admin '{current_user.username}' successfully created code: {code}.")

        return JSONResponse(content={
            'success': True,
            'message': f'Account created with code: {code}.',
            'code': code
        })
    except Exception as e:
        logging.error(f"Error creating hotspot code: {e}")
        db_conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='An error occurred.'
        )
    finally:
        if db_conn and db_conn.is_connected():
            cursor.close()
            db_conn.close()


@app.on_event("startup")
def startup_event():
    """Create tables and bootstrap admin on startup."""
    conn = None
    try:
        # First, connect to the MySQL server without specifying a database
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}`")
        cursor.close()
        conn.close()

        # Now, connect to the specific database and create tables
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            tables = {}
            tables['users'] = (
                "CREATE TABLE IF NOT EXISTS `users` (`id` int(11) NOT NULL AUTO_INCREMENT,`mac_address` varchar(17) NOT NULL UNIQUE,`expiry` datetime NOT NULL,`status` varchar(20) NOT NULL,`created_at` datetime NOT NULL,PRIMARY KEY (`id`)) ENGINE=InnoDB")
            tables['codes'] = (
                "CREATE TABLE IF NOT EXISTS `codes` (`id` int(11) NOT NULL AUTO_INCREMENT,`code` varchar(6) NOT NULL UNIQUE,`mac_address` varchar(17) DEFAULT NULL,`expiry` datetime NOT NULL,`status` varchar(20) NOT NULL,`created_at` datetime NOT NULL,PRIMARY KEY (`id`)) ENGINE=InnoDB")
            tables['payments'] = (
                "CREATE TABLE IF NOT EXISTS `payments` (`id` int(11) NOT NULL AUTO_INCREMENT,`transaction_id` varchar(255) NOT NULL UNIQUE,`phone_number` varchar(15) NOT NULL,`amount` decimal(10,2) NOT NULL,`mac_address` varchar(17) NOT NULL,`status` varchar(20) NOT NULL,`created_at` datetime NOT NULL,PRIMARY KEY (`id`)) ENGINE=InnoDB")
            tables['admins'] = (
                "CREATE TABLE IF NOT EXISTS `admins` (`id` INT(11) NOT NULL AUTO_INCREMENT,`username` VARCHAR(255) NOT NULL UNIQUE,`password_hash` VARCHAR(255) NOT NULL,PRIMARY KEY (`id`)) ENGINE=InnoDB")
            for name, ddl in tables.items():
                cursor.execute(ddl)
            conn.commit()
            cursor.close()

        # Bootstrap admin
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT COUNT(*) FROM admins")
            if cursor.fetchone()['COUNT(*)'] == 0:
                admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
                admin_password = os.environ.get('ADMIN_PASSWORD', 'password')
                hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')
                sql = "INSERT INTO admins (username, password_hash) VALUES (%s, %s)"
                val = (admin_username, hashed_password)
                cursor.execute(sql, val)
                conn.commit()
                logging.info(f"Initial admin '{admin_username}' created. Password is set from .env file.")
            cursor.close()
    except Exception as e:
        logging.error(f"Error during startup: {e}")
    finally:
        if conn and conn.is_connected():
            conn.close()


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)
