// This file has been updated to fetch the MAC address from a backend endpoint
// instead of generating a mock address.

const API_BASE_URL = 'https://surfspot.onrender.com/api';
const ADMIN_API_BASE_URL = `${API_BASE_URL}/admin`;

// A global variable to store the client's MAC address once it's fetched.
// This prevents multiple API calls for the same value.
let clientMacAddress = null;

// Utility function to show a modal
const showModal = (modalId) => {
    document.getElementById(modalId).style.display = 'flex';
};

// Utility function to hide a modal
const hideModal = (modalId) => {
    document.getElementById(modalId).style.display = 'none';
};

// New function to fetch a real MAC address from the backend.
// This function replaces the old mock MAC address generator.
const fetchClientMacAddress = async () => {
    // Check if the MAC address is already stored in the global variable or local storage
    if (clientMacAddress) {
        return clientMacAddress;
    }
    const macFromStorage = localStorage.getItem('client_mac_address');
    if (macFromStorage) {
        clientMacAddress = macFromStorage;
        return clientMacAddress;
    }

    // If not found, fetch it from the backend.
    showModal('check-subscription-modal');
    document.getElementById('check-subscription-title').textContent = 'Identifying your device...';
    document.getElementById('check-subscription-message').textContent = 'Please wait while we get your device address.';

    try {
        const response = await fetch(`${API_BASE_URL}/get_client_mac`);
        const data = await response.json();

        if (data.success && data.mac_address) {
            clientMacAddress = data.mac_address;
            localStorage.setItem('client_mac_address', clientMacAddress);
            return clientMacAddress;
        } else {
            console.error('Failed to fetch MAC address:', data.message);
            throw new Error(data.message || 'Failed to get MAC address from server.');
        }
    } catch (error) {
        console.error('Error fetching MAC address:', error);
        // Fallback to a placeholder or an error state if the backend call fails.
        // For a real captive portal, this would likely be a critical error.
        clientMacAddress = '00:00:00:00:00:00'; // A generic fallback
        return clientMacAddress;
    } finally {
        hideModal('check-subscription-modal');
    }
};

// --- User-facing functionality (STK Push & Code Login) ---

// Function to check if the client has an active subscription
const checkExistingSubscription = async () => {
    // Now uses the globally stored MAC address
    if (!clientMacAddress) return;

    showModal('check-subscription-modal');
    document.getElementById('check-subscription-title').textContent = 'Checking subscription...';
    document.getElementById('check-subscription-message').textContent = 'This should only take a moment.';

    try {
        const response = await fetch(`${API_BASE_URL}/check_mac_subscription`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac_address: clientMacAddress })
        });
        const data = await response.json();

        hideModal('check-subscription-modal');

        if (data.success && data.is_subscribed) {
            showModal('subscriber-status-modal');
            document.getElementById('subscriber-status-icon').innerHTML = `<span data-lucide="wifi" class="text-blue-500 w-16 h-16 mx-auto"></span>`;
            document.getElementById('subscriber-status-title').textContent = 'You are already connected!';
            document.getElementById('subscriber-status-message').textContent = `Your subscription is active until ${new Date(data.expiry).toLocaleString()}. Enjoy your browsing!`;
            document.getElementById('subscriber-status-action-btn').textContent = 'Okay';
            document.getElementById('subscriber-status-action-btn').onclick = () => hideModal('subscriber-status-modal');
        }
    } catch (error) {
        console.error('Error checking subscription:', error);
        hideModal('check-subscription-modal');
    } finally {
        lucide.createIcons();
    }
};

// Event listeners for opening the phone number input modal
document.querySelectorAll('.open-phone-modal-btn').forEach(button => {
    button.addEventListener('click', (event) => {
        const planPrice = event.currentTarget.dataset.planPrice;
        const planName = event.currentTarget.dataset.planName;
        document.getElementById('phone-input-modal').dataset.selectedPlanPrice = planPrice;
        document.getElementById('phone-input-modal').dataset.selectedPlanName = planName;
        document.getElementById('plan-name').textContent = `${planName} for KSh ${planPrice}`;
        showModal('phone-input-modal');
    });
});

// Event listener for submitting the phone number
document.getElementById('submit-phone-number').addEventListener('click', async () => {
    const phoneNumber = document.getElementById('phoneNumber').value;
    const planPrice = document.getElementById('phone-input-modal').dataset.selectedPlanPrice;
    const messageEl = document.getElementById('phone-modal-message');
    messageEl.textContent = '';
    messageEl.className = 'mt-4 text-sm font-medium';

    if (!phoneNumber || !/^(?:01|07)\d{8}$/.test(phoneNumber)) {
        messageEl.textContent = 'Please enter a valid Safaricom phone number.';
        messageEl.className = 'mt-4 text-sm font-medium text-red-400';
        return;
    }

    hideModal('phone-input-modal');
    showModal('stk-initiated-modal');

    try {
        const response = await fetch(`${API_BASE_URL}/initiate_payment`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            // Use the global clientMacAddress
            body: JSON.stringify({ phone_number: phoneNumber, amount: planPrice, mac_address: clientMacAddress })
        });

        const data = await response.json();
        hideModal('stk-initiated-modal');
        showModal('stk-status-modal');

        const statusTitle = document.getElementById('stk-status-title');
        const statusMessage = document.getElementById('stk-status-message');
        const statusIcon = document.getElementById('stk-status-icon');
        const statusBtn = document.getElementById('stk-status-action-btn');

        if (data.success) {
            statusIcon.innerHTML = `<span data-lucide="check-circle" class="text-green-500 w-16 h-16 mx-auto"></span>`;
            statusTitle.textContent = 'Payment Request Sent!';
            statusMessage.textContent = 'Please check your phone and enter your M-Pesa PIN to complete the transaction.';
            statusBtn.textContent = 'Close';
            statusBtn.onclick = () => hideModal('stk-status-modal');

        } else {
            statusIcon.innerHTML = `<span data-lucide="x-circle" class="text-red-500 w-16 h-16 mx-auto"></span>`;
            statusTitle.textContent = 'Transaction Failed';
            statusMessage.textContent = data.message || 'An unexpected error occurred.';
            statusBtn.textContent = 'Try Again';
            statusBtn.onclick = () => {
                hideModal('stk-status-modal');
                showModal('phone-input-modal');
            };
        }
        lucide.createIcons();

    } catch (error) {
        hideModal('stk-initiated-modal');
        showModal('stk-status-modal');

        document.getElementById('stk-status-icon').innerHTML = `<span data-lucide="alert-triangle" class="text-yellow-500 w-16 h-16 mx-auto"></span>`;
        document.getElementById('stk-status-title').textContent = 'Connection Error';
        document.getElementById('stk-status-message').textContent = 'Failed to connect to the server. Please try again later.';
        document.getElementById('stk-status-action-btn').textContent = 'Close';
        document.getElementById('stk-status-action-btn').onclick = () => hideModal('stk-status-modal');
        lucide.createIcons();

        console.error('STK Push Error:', error);
    }
});

// Event listener for connecting with a code
document.getElementById('connectWithCodeBtn').addEventListener('click', async () => {
    const code = document.getElementById('subscriberCodeInput').value;
    const messageEl = document.getElementById('message-box');
    const messageTextEl = document.getElementById('message-text');
    messageEl.style.display = 'block';
    messageTextEl.textContent = 'Connecting...';
    messageEl.className = 'mt-8 p-4 rounded-lg bg-blue-500';

    try {
        const response = await fetch(`${API_BASE_URL}/connect_with_code`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            // Use the global clientMacAddress
            body: JSON.stringify({ code: code, mac_address: clientMacAddress })
        });
        const data = await response.json();

        if (data.success) {
            messageTextEl.textContent = data.message;
            messageEl.className = 'mt-8 p-4 rounded-lg bg-green-500';
        } else {
            messageTextEl.textContent = data.message;
            messageEl.className = 'mt-8 p-4 rounded-lg bg-red-500';
        }
    } catch (error) {
        messageTextEl.textContent = 'Failed to connect to the server. Please try again later.';
        messageEl.className = 'mt-8 p-4 rounded-lg bg-red-500';
        console.error('Code Login Error:', error);
    }
});

// Event listener for closing modals
document.getElementById('close-phone-input').addEventListener('click', () => hideModal('phone-input-modal'));
document.getElementById('close-stk-status').addEventListener('click', () => hideModal('stk-status-modal'));
document.getElementById('close-subscriber-status').addEventListener('click', () => hideModal('subscriber-status-modal'));
document.getElementById('close-admin-login').addEventListener('click', () => hideModal('admin-login-modal'));
document.getElementById('close-admin-dashboard').addEventListener('click', () => hideModal('admin-dashboard-modal'));
document.getElementById('stk-status-action-btn').addEventListener('click', () => hideModal('stk-status-modal'));


// --- Admin Dashboard Functionality ---

// Open Admin Login Modal
document.getElementById('admin-login-btn').addEventListener('click', () => {
    showModal('admin-login-modal');
});

// Admin Logout
document.getElementById('admin-logout-btn').addEventListener('click', () => {
    localStorage.removeItem('admin_token');
    hideModal('admin-dashboard-modal');
});

// Handle Admin Login
document.getElementById('admin-login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = document.getElementById('admin-username').value;
    const password = document.getElementById('admin-password').value;
    const messageEl = document.getElementById('admin-login-message');
    messageEl.textContent = '';

    try {
        const response = await fetch(`${ADMIN_API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();

        if (data.success) {
            localStorage.setItem('admin_token', data.token);
            hideModal('admin-login-modal');
            showModal('admin-dashboard-modal');
            fetchActiveUsers();
        } else {
            messageEl.textContent = data.message;
        }
    } catch (error) {
        messageEl.textContent = 'Failed to connect to the server.';
        console.error('Admin Login Error:', error);
    }
});

// Fetch and display active users
const fetchActiveUsers = async () => {
    const token = localStorage.getItem('admin_token');
    const tableContainer = document.getElementById('mikrotik-users-table');
    if (!token) return;

    tableContainer.innerHTML = `<p class="text-center text-gray-500">Loading active users...</p>`;

    try {
        const response = await fetch(`${ADMIN_API_BASE_URL}/get_mikrotik_users`, {
            headers: { 'x-access-tokens': token }
        });

        if (response.status === 401) {
            localStorage.removeItem('admin_token');
            hideModal('admin-dashboard-modal');
            showModal('admin-login-modal');
            document.getElementById('admin-login-message').textContent = 'Session expired. Please log in again.';
            return;
        }

        const data = await response.json();
        if (data.success) {
            if (data.users.length > 0) {
                let tableHtml = `
                    <table class="min-w-full divide-y divide-gray-700">
                        <thead>
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">IP Address</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">MAC Address</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Uptime</th>
                            </tr>
                        </thead>
                        <tbody class="bg-gray-900 divide-y divide-gray-700">
                `;
                data.users.forEach(user => {
                    tableHtml += `
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-200">${user.ip}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">${user.mac_address}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">${user.uptime}</td>
                        </tr>
                    `;
                });
                tableHtml += `</tbody></table>`;
                tableContainer.innerHTML = tableHtml;
            } else {
                tableContainer.innerHTML = `<p class="text-center text-gray-500 p-4">No active users found on the MikroTik router.</p>`;
            }
        } else {
            tableContainer.innerHTML = `<p class="text-center text-red-400">Failed to fetch users: ${data.message}</p>`;
        }
    } catch (error) {
        console.error('Fetch users error:', error);
        tableContainer.innerHTML = `<p class="text-center text-red-400">Failed to connect to the server.</p>`;
    }
};

// Handle creating a new hotspot code
document.getElementById('create-account-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const macAddress = document.getElementById('new-account-mac').value;
    const expiryDays = document.getElementById('new-account-expiry').value;
    const messageEl = document.getElementById('create-account-message');
    messageEl.textContent = 'Generating code...';
    messageEl.className = 'mt-4 text-sm font-medium text-blue-400';

    const token = localStorage.getItem('admin_token');
    if (!token) {
         messageEl.textContent = 'Not authenticated. Please log in.';
         messageEl.className = 'mt-4 text-sm font-medium text-red-400';
         return;
    }

    const body = {
        expiry_days: parseInt(expiryDays)
    };
    if (macAddress) {
        body.mac_address = macAddress;
    }

    try {
        const response = await fetch(`${ADMIN_API_BASE_URL}/create_hotspot_code`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-access-tokens': token
            },
            body: JSON.stringify(body)
        });

        if (response.status === 401) {
            localStorage.removeItem('admin_token');
            hideModal('admin-dashboard-modal');
            showModal('admin-login-modal');
            document.getElementById('admin-login-message').textContent = 'Session expired. Please log in again.';
            return;
        }

        const data = await response.json();
        if (data.success) {
            messageEl.innerHTML = `<p class="text-green-400 font-bold">${data.message} The code is: <code class="bg-gray-700 text-lg p-1 rounded">${data.code}</code></p>`;
            document.getElementById('new-account-mac').value = '';
        } else {
            messageEl.textContent = data.message;
            messageEl.className = 'mt-4 text-sm font-medium text-red-400';
        }
    } catch (error) {
        messageEl.textContent = 'Failed to connect to the server.';
        messageEl.className = 'mt-4 text-sm font-medium text-red-400';
        console.error('Create Code Error:', error);
    }
});

// Handle changing admin password
document.getElementById('change-password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const oldPassword = document.getElementById('old-password').value;
    const newPassword = document.getElementById('new-password').value;
    const messageEl = document.getElementById('change-password-message');
    messageEl.textContent = 'Changing password...';
    messageEl.className = 'mt-4 text-sm font-medium text-blue-400';

    const token = localStorage.getItem('admin_token');
    if (!token) {
         messageEl.textContent = 'Not authenticated. Please log in.';
         messageEl.className = 'mt-4 text-sm font-medium text-red-400';
         return;
    }

    try {
        const response = await fetch(`${ADMIN_API_BASE_URL}/change_password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-access-tokens': token
            },
            body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
        });

        if (response.status === 401) {
            localStorage.removeItem('admin_token');
            hideModal('admin-dashboard-modal');
            showModal('admin-login-modal');
            document.getElementById('admin-login-message').textContent = 'Session expired. Please log in again.';
            return;
        }

        const data = await response.json();
        if (data.success) {
            messageEl.textContent = data.message;
            messageEl.className = 'mt-4 text-sm font-medium text-green-400';
            document.getElementById('change-password-form').reset();
        } else {
            messageEl.textContent = data.message;
            messageEl.className = 'mt-4 text-sm font-medium text-red-400';
        }
    } catch (error) {
        messageEl.textContent = 'Failed to connect to the server.';
        messageEl.className = 'mt-4 text-sm font-medium text-red-400';
        console.error('Change Password Error:', error);
    }
});

// Handle updating admin credentials
document.getElementById('update-credentials-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const newUsername = document.getElementById('update-username').value;
    const newPassword = document.getElementById('update-password').value;
    const messageEl = document.getElementById('update-credentials-message');
    messageEl.textContent = 'Updating credentials...';
    messageEl.className = 'mt-4 text-sm font-medium text-blue-400';

    const token = localStorage.getItem('admin_token');
    if (!token) {
         messageEl.textContent = 'Not authenticated. Please log in.';
         messageEl.className = 'mt-4 text-sm font-medium text-red-400';
         return;
    }

    try {
        const response = await fetch(`${ADMIN_API_BASE_URL}/update_credentials`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-access-tokens': token
            },
            body: JSON.stringify({ username: newUsername, password: newPassword })
        });

        if (response.status === 401) {
            localStorage.removeItem('admin_token');
            hideModal('admin-dashboard-modal');
            showModal('admin-login-modal');
            document.getElementById('admin-login-message').textContent = 'Session expired. Please log in again.';
            return;
        }

        const data = await response.json();
        if (data.success) {
            messageEl.textContent = data.message;
            messageEl.className = 'mt-4 text-sm font-medium text-green-400';
            document.getElementById('update-credentials-form').reset();
        } else {
            messageEl.textContent = data.message;
            messageEl.className = 'mt-4 text-sm font-medium text-red-400';
        }
    } catch (error) {
        messageEl.textContent = 'Failed to connect to the server.';
        messageEl.className = 'mt-4 text-sm font-medium text-red-400';
        console.error('Update Credentials Error:', error);
    }
});


// Back to top button functionality
const backToTopBtn = document.getElementById('back-to-top-btn');
window.addEventListener('scroll', () => {
  if (window.scrollY > 300) {
    backToTopBtn.style.display = 'block';
  } else {
    backToTopBtn.style.display = 'none';
  }
});

backToTopBtn.addEventListener('click', () => {
  window.scrollTo({
    top: 0,
    behavior: 'smooth'
  });
});

// Initial check for subscription and create Lucide icons on page load
window.onload = async () => {
    // First, get the client's MAC address from the backend
    await fetchClientMacAddress();

    // Now, with the MAC address available, check for an existing subscription
    checkExistingSubscription();

    // Create Lucide icons
    lucide.createIcons();
};

// We've removed the old getClientMacAddress function as it is no longer needed.
// The new fetchClientMacAddress function handles fetching and storing the MAC address.
// Other functions now use the global `clientMacAddress` variable, which is populated on page load.
