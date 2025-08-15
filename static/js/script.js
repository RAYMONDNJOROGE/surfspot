 // --- Refactored JavaScript Code ---

        // Constants for API URLs
        const API_BASE_URL = 'https://surfspot.onrender.com/api';
        const ADMIN_API_BASE_URL = `${API_BASE_URL}/admin`;

        // Constants for DOM element IDs to improve readability and maintainability
        const DOM_ELEMENTS = {
            MODALS: {
                PHONE_INPUT: 'phone-input-modal',
                STK_INITIATED: 'stk-initiated-modal',
                STK_STATUS: 'stk-status-modal',
                SUBSCRIBER_STATUS: 'subscriber-status-modal',
                CHECK_SUBSCRIPTION: 'check-subscription-modal',
                ADMIN_LOGIN: 'admin-login-modal',
                ADMIN_DASHBOARD: 'admin-dashboard-modal',
            },
            BUTTONS: {
                PHONE_INPUT_OPEN: '.open-phone-modal-btn',
                PHONE_INPUT_SUBMIT: 'submit-phone-number',
                CONNECT_WITH_CODE: 'connectWithCodeBtn',
                ADMIN_LOGIN_OPEN: 'admin-login-btn',
                ADMIN_LOGOUT: 'admin-logout-btn',
                BACK_TO_TOP: 'back-to-top-btn',
                CLOSE_ADMIN_DASHBOARD: 'close-admin-dashboard'
            },
            FORMS: {
                ADMIN_LOGIN: 'admin-login-form',
                CREATE_ACCOUNT: 'create-account-form',
                CHANGE_PASSWORD: 'change-password-form',
                UPDATE_CREDENTIALS: 'update-credentials-form',
            },
            INPUTS: {
                PHONE_NUMBER: 'phoneNumber',
                SUBSCRIBER_CODE: 'subscriberCodeInput',
                ADMIN_USERNAME: 'admin-username',
                ADMIN_PASSWORD: 'admin-password',
                NEW_ACCOUNT_MAC: 'new-account-mac',
                NEW_ACCOUNT_EXPIRY: 'new-account-expiry',
                OLD_PASSWORD: 'old-password',
                NEW_PASSWORD: 'new-password',
                UPDATE_USERNAME: 'update-username',
                UPDATE_PASSWORD: 'update-password',
            },
            MESSAGES: {
                PHONE_MODAL: 'phone-modal-message',
                STK_STATUS: {
                    ICON: 'stk-status-icon',
                    TITLE: 'stk-status-title',
                    MESSAGE: 'stk-status-message',
                    ACTION_BTN: 'stk-status-action-btn',
                },
                SUBSCRIBER_STATUS: {
                    ICON: 'subscriber-status-icon',
                    TITLE: 'subscriber-status-title',
                    MESSAGE: 'subscriber-status-message',
                    ACTION_BTN: 'subscriber-status-action-btn',
                },
                CODE_LOGIN: {
                    BOX: 'message-box',
                    TEXT: 'message-text',
                },
                ADMIN: {
                    LOGIN: 'admin-login-message',
                    CREATE_ACCOUNT: 'create-account-message',
                    CHANGE_PASSWORD: 'change-password-message',
                    UPDATE_CREDENTIALS: 'update-credentials-message',
                },
            },
            TABLES: {
                MIKROTIK_USERS: 'mikrotik-users-table',
            },
            TEXT: {
                PLAN_NAME: 'plan-name',
            }
        };

        // --- Utility Functions ---

        /**
         * Shows a modal by setting its display style to 'flex'.
         * @param {string} modalId - The ID of the modal to show.
         */
        const showModal = (modalId) => {
            document.getElementById(modalId).style.display = 'flex';
        };

        /**
         * Hides a modal by setting its display style to 'none'.
         * @param {string} modalId - The ID of the modal to hide.
         */
        const hideModal = (modalId) => {
            document.getElementById(modalId).style.display = 'none';
        };

        /**
         * Simulates a client's unique MAC address.
         * In a real captive portal, this would be provided by the network.
         * @returns {string} The client's MAC address.
         */
        const getClientMacAddress = () => {
            let mac = localStorage.getItem('client_mac_address');
            if (!mac) {
                mac = '02:00:00:' + Array(3).fill(0).map(() => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':');
                localStorage.setItem('client_mac_address', mac);
            }
            return mac;
        };

        /**
         * Centralized function to handle authentication errors (401).
         * @param {Response} response - The API response object.
         * @returns {boolean} True if an auth error occurred, false otherwise.
         */
        const handleUnauthorized = (response) => {
            if (response.status === 401) {
                localStorage.removeItem('admin_token');
                hideModal(DOM_ELEMENTS.MODALS.ADMIN_DASHBOARD);
                showModal(DOM_ELEMENTS.MODALS.ADMIN_LOGIN);
                document.getElementById(DOM_ELEMENTS.MESSAGES.ADMIN.LOGIN).textContent = 'Session expired. Please log in again.';
                return true;
            }
            return false;
        };

        /**
         * Utility function to fetch data with the admin token.
         * It automatically handles the token header and unauthorized errors.
         * @param {string} url - The API endpoint URL.
         * @param {object} options - Fetch options (method, body, etc.).
         * @returns {Promise<Response>} The fetch response object.
         */
        const fetchWithAuth = async (url, options = {}) => {
            const token = localStorage.getItem('admin_token');
            if (!token) {
                // If there's no token, a call to this function indicates an auth failure.
                // We'll throw an error which will be caught by the calling function's catch block.
                throw new Error('Not authenticated.');
            }

            const headers = {
                'x-access-tokens': token,
                ...options.headers,
            };

            const response = await fetch(url, { ...options, headers });
            if (handleUnauthorized(response)) {
                return null; // Return null to signal that the request was handled.
            }
            return response;
        };


        // --- User-facing Functionality ---

        /**
         * Checks for an existing subscription on page load.
         */
        const checkExistingSubscription = async () => {
            const macAddress = getClientMacAddress();
            showModal(DOM_ELEMENTS.MODALS.CHECK_SUBSCRIPTION);

            try {
                const response = await fetch(`${API_BASE_URL}/check_mac_subscription`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mac_address: macAddress })
                });
                const data = await response.json();

                hideModal(DOM_ELEMENTS.MODALS.CHECK_SUBSCRIPTION);

                if (data.success && data.is_subscribed) {
                    showModal(DOM_ELEMENTS.MODALS.SUBSCRIBER_STATUS);
                    document.getElementById(DOM_ELEMENTS.MESSAGES.SUBSCRIBER_STATUS.ICON).innerHTML = `<span data-lucide="check-circle" class="text-emerald-500 w-16 h-16 mx-auto"></span>`;
                    document.getElementById(DOM_ELEMENTS.MESSAGES.SUBSCRIBER_STATUS.TITLE).textContent = 'You are already connected!';
                    document.getElementById(DOM_ELEMENTS.MESSAGES.SUBSCRIBER_STATUS.MESSAGE).textContent = `Your subscription is active until ${new Date(data.expiry).toLocaleString()}. Enjoy your browsing!`;
                    document.getElementById(DOM_ELEMENTS.MESSAGES.SUBSCRIBER_STATUS.ACTION_BTN).textContent = 'Okay';
                    document.getElementById(DOM_ELEMENTS.MESSAGES.SUBSCRIBER_STATUS.ACTION_BTN).onclick = () => hideModal(DOM_ELEMENTS.MODALS.SUBSCRIBER_STATUS);
                }
            } catch (error) {
                console.error('Error checking subscription:', error);
                hideModal(DOM_ELEMENTS.MODALS.CHECK_SUBSCRIPTION);
            } finally {
                lucide.createIcons();
            }
        };

        // Event listener for opening the phone number input modal
        document.querySelectorAll(DOM_ELEMENTS.BUTTONS.PHONE_INPUT_OPEN).forEach(button => {
            button.addEventListener('click', (event) => {
                const planPrice = event.currentTarget.dataset.planPrice;
                const planName = event.currentTarget.dataset.planName;
                document.getElementById(DOM_ELEMENTS.MODALS.PHONE_INPUT).dataset.selectedPlanPrice = planPrice;
                document.getElementById(DOM_ELEMENTS.MODALS.PHONE_INPUT).dataset.selectedPlanName = planName;
                document.getElementById(DOM_ELEMENTS.TEXT.PLAN_NAME).textContent = `${planName} for KSh ${planPrice}`;
                showModal(DOM_ELEMENTS.MODALS.PHONE_INPUT);
            });
        });

        // Event listener for submitting the phone number
        document.getElementById(DOM_ELEMENTS.BUTTONS.PHONE_INPUT_SUBMIT).addEventListener('click', async () => {
            const macAddress = getClientMacAddress();
            const phoneNumber = document.getElementById(DOM_ELEMENTS.INPUTS.PHONE_NUMBER).value;
            const planPrice = document.getElementById(DOM_ELEMENTS.MODALS.PHONE_INPUT).dataset.selectedPlanPrice;
            const messageEl = document.getElementById(DOM_ELEMENTS.MESSAGES.PHONE_MODAL);
            messageEl.textContent = '';
            messageEl.className = 'mt-4 text-sm font-medium';

            if (!phoneNumber || !/^(?:01|07)\d{8}$/.test(phoneNumber)) {
                messageEl.textContent = 'Please enter a valid Safaricom phone number.';
                messageEl.className = 'mt-4 text-sm font-medium text-red-400';
                return;
            }

            hideModal(DOM_ELEMENTS.MODALS.PHONE_INPUT);
            showModal(DOM_ELEMENTS.MODALS.STK_INITIATED);

            try {
                const response = await fetch(`${API_BASE_URL}/initiate_payment`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ phone_number: phoneNumber, amount: planPrice, mac_address: macAddress })
                });

                const data = await response.json();
                hideModal(DOM_ELEMENTS.MODALS.STK_INITIATED);
                showModal(DOM_ELEMENTS.MODALS.STK_STATUS);

                const statusTitle = document.getElementById(DOM_ELEMENTS.MESSAGES.STK_STATUS.TITLE);
                const statusMessage = document.getElementById(DOM_ELEMENTS.MESSAGES.STK_STATUS.MESSAGE);
                const statusIcon = document.getElementById(DOM_ELEMENTS.MESSAGES.STK_STATUS.ICON);
                const statusBtn = document.getElementById(DOM_ELEMENTS.MESSAGES.STK_STATUS.ACTION_BTN);

                if (data.success) {
                    statusIcon.innerHTML = `<span data-lucide="check-circle" class="text-emerald-500 w-16 h-16 mx-auto"></span>`;
                    statusTitle.textContent = 'Payment Request Sent!';
                    statusMessage.textContent = 'Please check your phone and enter your M-Pesa PIN to complete the transaction.';
                    statusBtn.textContent = 'Close';
                    statusBtn.onclick = () => hideModal(DOM_ELEMENTS.MODALS.STK_STATUS);
                } else {
                    statusIcon.innerHTML = `<span data-lucide="x-circle" class="text-rose-500 w-16 h-16 mx-auto"></span>`;
                    statusTitle.textContent = 'Transaction Failed';
                    statusMessage.textContent = data.message || 'An unexpected error occurred.';
                    statusBtn.textContent = 'Try Again';
                    statusBtn.onclick = () => {
                        hideModal(DOM_ELEMENTS.MODALS.STK_STATUS);
                        showModal(DOM_ELEMENTS.MODALS.PHONE_INPUT);
                    };
                }
            } catch (error) {
                hideModal(DOM_ELEMENTS.MODALS.STK_INITIATED);
                showModal(DOM_ELEMENTS.MODALS.STK_STATUS);
                document.getElementById(DOM_ELEMENTS.MESSAGES.STK_STATUS.ICON).innerHTML = `<span data-lucide="alert-triangle" class="text-yellow-500 w-16 h-16 mx-auto"></span>`;
                document.getElementById(DOM_ELEMENTS.MESSAGES.STK_STATUS.TITLE).textContent = 'Connection Error';
                document.getElementById(DOM_ELEMENTS.MESSAGES.STK_STATUS.MESSAGE).textContent = 'Failed to connect to the server. Please try again later.';
                document.getElementById(DOM_ELEMENTS.MESSAGES.STK_STATUS.ACTION_BTN).textContent = 'Close';
                document.getElementById(DOM_ELEMENTS.MESSAGES.STK_STATUS.ACTION_BTN).onclick = () => hideModal(DOM_ELEMENTS.MODALS.STK_STATUS);
                console.error('STK Push Error:', error);
            } finally {
                lucide.createIcons();
            }
        });

        // Event listener for connecting with a code
        document.getElementById(DOM_ELEMENTS.BUTTONS.CONNECT_WITH_CODE).addEventListener('click', async () => {
            const macAddress = getClientMacAddress();
            const code = document.getElementById(DOM_ELEMENTS.INPUTS.SUBSCRIBER_CODE).value;
            const messageEl = document.getElementById(DOM_ELEMENTS.MESSAGES.CODE_LOGIN.BOX);
            const messageTextEl = document.getElementById(DOM_ELEMENTS.MESSAGES.CODE_LOGIN.TEXT);
            messageEl.style.display = 'block';
            messageTextEl.textContent = 'Connecting...';
            messageEl.className = 'mt-8 p-4 rounded-lg bg-violet-600 text-white';

            try {
                const response = await fetch(`${API_BASE_URL}/connect_with_code`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: code, mac_address: macAddress })
                });
                const data = await response.json();

                if (data.success) {
                    messageTextEl.textContent = data.message;
                    messageEl.className = 'mt-8 p-4 rounded-lg bg-emerald-600 text-white';
                } else {
                    messageTextEl.textContent = data.message;
                    messageEl.className = 'mt-8 p-4 rounded-lg bg-rose-600 text-white';
                }
            } catch (error) {
                messageTextEl.textContent = 'Failed to connect to the server. Please try again later.';
                messageEl.className = 'mt-8 p-4 rounded-lg bg-rose-600 text-white';
                console.error('Code Login Error:', error);
            }
        });

        // Close Admin Login and Dashboard Modals
        document.getElementById('close-admin-login').addEventListener('click', () => hideModal(DOM_ELEMENTS.MODALS.ADMIN_LOGIN));
        document.getElementById(DOM_ELEMENTS.BUTTONS.CLOSE_ADMIN_DASHBOARD).addEventListener('click', () => hideModal(DOM_ELEMENTS.MODALS.ADMIN_DASHBOARD));

        // --- Admin Dashboard Functionality ---

        // Open Admin Login Modal
        document.getElementById(DOM_ELEMENTS.BUTTONS.ADMIN_LOGIN_OPEN).addEventListener('click', () => {
            showModal(DOM_ELEMENTS.MODALS.ADMIN_LOGIN);
        });

        // Admin Logout
        document.getElementById(DOM_ELEMENTS.BUTTONS.ADMIN_LOGOUT).addEventListener('click', () => {
            localStorage.removeItem('admin_token');
            hideModal(DOM_ELEMENTS.MODALS.ADMIN_DASHBOARD);
        });

        // Handle Admin Login
        document.getElementById(DOM_ELEMENTS.FORMS.ADMIN_LOGIN).addEventListener('submit', async (event) => {
            event.preventDefault();
            const username = document.getElementById(DOM_ELEMENTS.INPUTS.ADMIN_USERNAME).value;
            const password = document.getElementById(DOM_ELEMENTS.INPUTS.ADMIN_PASSWORD).value;
            const messageEl = document.getElementById(DOM_ELEMENTS.MESSAGES.ADMIN.LOGIN);
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
                    hideModal(DOM_ELEMENTS.MODALS.ADMIN_LOGIN);
                    showModal(DOM_ELEMENTS.MODALS.ADMIN_DASHBOARD);
                    fetchActiveUsers();
                } else {
                    messageEl.textContent = data.message;
                }
            } catch (error) {
                messageEl.textContent = 'Failed to connect to the server.';
                console.error('Admin Login Error:', error);
            }
        });

        /**
         * Fetches and displays active users on the MikroTik router.
         */
        const fetchActiveUsers = async () => {
            const tableContainer = document.getElementById(DOM_ELEMENTS.TABLES.MIKROTIK_USERS);
            tableContainer.innerHTML = `<p class="text-center text-gray-500">Loading active users...</p>`;

            try {
                const response = await fetchWithAuth(`${ADMIN_API_BASE_URL}/get_mikrotik_users`);
                if (!response) return; // Exit if unauthorized

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
        document.getElementById(DOM_ELEMENTS.FORMS.CREATE_ACCOUNT).addEventListener('submit', async (event) => {
            event.preventDefault();
            const macAddress = document.getElementById(DOM_ELEMENTS.INPUTS.NEW_ACCOUNT_MAC).value;
            const expiryDays = document.getElementById(DOM_ELEMENTS.INPUTS.NEW_ACCOUNT_EXPIRY).value;
            const messageEl = document.getElementById(DOM_ELEMENTS.MESSAGES.ADMIN.CREATE_ACCOUNT);
            messageEl.textContent = 'Generating code...';
            messageEl.className = 'mt-4 text-sm font-medium text-violet-400';

            const body = {
                expiry_days: parseInt(expiryDays)
            };
            if (macAddress) {
                body.mac_address = macAddress;
            }

            try {
                const response = await fetchWithAuth(`${ADMIN_API_BASE_URL}/create_hotspot_code`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                if (!response) return;

                const data = await response.json();
                if (data.success) {
                    messageEl.innerHTML = `<p class="text-emerald-400 font-bold">${data.message} The code is: <code class="bg-gray-700 text-lg p-1 rounded">${data.code}</code></p>`;
                    document.getElementById(DOM_ELEMENTS.INPUTS.NEW_ACCOUNT_MAC).value = '';
                } else {
                    messageEl.textContent = data.message;
                    messageEl.className = 'mt-4 text-sm font-medium text-rose-400';
                }
            } catch (error) {
                messageEl.textContent = 'Failed to connect to the server.';
                messageEl.className = 'mt-4 text-sm font-medium text-rose-400';
                console.error('Create Code Error:', error);
            }
        });

        // Handle changing admin password
        document.getElementById(DOM_ELEMENTS.FORMS.CHANGE_PASSWORD).addEventListener('submit', async (event) => {
            event.preventDefault();
            const oldPassword = document.getElementById(DOM_ELEMENTS.INPUTS.OLD_PASSWORD).value;
            const newPassword = document.getElementById(DOM_ELEMENTS.INPUTS.NEW_PASSWORD).value;
            const messageEl = document.getElementById(DOM_ELEMENTS.MESSAGES.ADMIN.CHANGE_PASSWORD);
            messageEl.textContent = 'Changing password...';
            messageEl.className = 'mt-4 text-sm font-medium text-violet-400';

            try {
                const response = await fetchWithAuth(`${ADMIN_API_BASE_URL}/change_password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
                });
                if (!response) return;

                const data = await response.json();
                if (data.success) {
                    messageEl.textContent = data.message;
                    messageEl.className = 'mt-4 text-sm font-medium text-emerald-400';
                    document.getElementById(DOM_ELEMENTS.FORMS.CHANGE_PASSWORD).reset();
                } else {
                    messageEl.textContent = data.message;
                    messageEl.className = 'mt-4 text-sm font-medium text-rose-400';
                }
            } catch (error) {
                messageEl.textContent = 'Failed to connect to the server.';
                messageEl.className = 'mt-4 text-sm font-medium text-rose-400';
                console.error('Change Password Error:', error);
            }
        });

        // Handle updating admin credentials
        document.getElementById(DOM_ELEMENTS.FORMS.UPDATE_CREDENTIALS).addEventListener('submit', async (event) => {
            event.preventDefault();
            const newUsername = document.getElementById(DOM_ELEMENTS.INPUTS.UPDATE_USERNAME).value;
            const newPassword = document.getElementById(DOM_ELEMENTS.INPUTS.UPDATE_PASSWORD).value;
            const messageEl = document.getElementById(DOM_ELEMENTS.MESSAGES.ADMIN.UPDATE_CREDENTIALS);
            messageEl.textContent = 'Updating credentials...';
            messageEl.className = 'mt-4 text-sm font-medium text-violet-400';

            try {
                const response = await fetchWithAuth(`${ADMIN_API_BASE_URL}/update_credentials`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: newUsername, password: newPassword })
                });
                if (!response) return;

                const data = await response.json();
                if (data.success) {
                    messageEl.textContent = data.message;
                    messageEl.className = 'mt-4 text-sm font-medium text-emerald-400';
                    document.getElementById(DOM_ELEMENTS.FORMS.UPDATE_CREDENTIALS).reset();
                } else {
                    messageEl.textContent = data.message;
                    messageEl.className = 'mt-4 text-sm font-medium text-rose-400';
                }
            } catch (error) {
                messageEl.textContent = 'Failed to connect to the server.';
                messageEl.className = 'mt-4 text-sm font-medium text-rose-400';
                console.error('Update Credentials Error:', error);
            }
        });

        // Back to top button functionality
        const backToTopBtn = document.getElementById(DOM_ELEMENTS.BUTTONS.BACK_TO_TOP);
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
        window.onload = () => {
            checkExistingSubscription();
            lucide.createIcons();
        };