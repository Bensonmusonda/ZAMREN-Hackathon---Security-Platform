// scripts/spam_logic.js

document.addEventListener('DOMContentLoaded', async () => {
    const SERVER_IP = "192.168.56.1"
    const MAIN_IDS_BASE_URL = `http://${SERVER_IP}:8000`; // Ensure this matches your FastAPI backend URL
    const messageViewTypeSelect = document.getElementById('message-view-type');
    const messageListContainer = document.querySelector('.message-list-container');
    const inboxTitle = document.querySelector('.inbox-title'); // Keep this class, just change the text
    const userDisplayName = document.getElementById('user-display-name');
    const logoutButton = document.getElementById('logout-button');

    // --- Authentication Check ---
    const token = localStorage.getItem('access_token');
    if (!token) {
        alert('You are not logged in. Please log in to access your spam folder.'); // Updated alert
        window.location.href = 'login.html';
        return; // Stop execution
    }

    // --- Helper function to handle unauthorized responses ---
    async function handleUnauthorized(response) {
        if (response.status === 401) {
            localStorage.removeItem('access_token'); // Clear invalid token
            alert('Your session has expired or is invalid. Please log in again.');
            window.location.href = 'login.html';
            return true; // Indicates that a redirect occurred
        }
        return false; // Indicates no redirect occurred
    }

    // --- Function to fetch and display user info (e.g., name) ---
    async function fetchUserInfo() {
        try {
            const response = await fetch(`${MAIN_IDS_BASE_URL}/current_user`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (await handleUnauthorized(response)) return;

            if (!response.ok) {
                throw new Error(`Failed to fetch user info: ${response.status}`);
            }

            const userData = await response.json();
            userDisplayName.textContent = `${userData.first_name} ${userData.last_name}`;
        } catch (error) {
            console.error('Error fetching user info:', error);
            userDisplayName.textContent = 'User Info Error';
        }
    }

    // --- Function to fetch messages (Emails or SMS) ---
    async function fetchMessages(type) {
        messageListContainer.innerHTML = '<p class="loading-message">Loading messages...</p>';
        // Update title based on selected type
        if (type === 'email-spam') {
            inboxTitle.textContent = 'Your Email Spam';
        } else if (type === 'sms-spam') {
            inboxTitle.textContent = 'Your SMS Spam';
        }

        let url = '';
        if (type === 'email-spam') {
            url = `${MAIN_IDS_BASE_URL}/user/emails/spam`; // <-- NEW URL for email spam
        } else if (type === 'sms-spam') {
            url = `${MAIN_IDS_BASE_URL}/user/sms/spam`; // <-- NEW URL for SMS spam
        }

        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (await handleUnauthorized(response)) return;

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`HTTP error! Status: ${response.status}, Detail: ${errorData.detail || response.statusText}`);
            }

            const messages = await response.json();
            displayMessages(messages, type);
        } catch (error) {
            console.error('Error fetching messages:', error);
            messageListContainer.innerHTML = `<p class="error-message">Failed to load messages: ${error.message}. Please ensure the backend is running and you are logged in.</p>`;
        }
    }

    // --- Function to render messages in the UI ---
    function displayMessages(messages, type) {
        messageListContainer.innerHTML = '';

        if (messages.length === 0) {
            messageListContainer.innerHTML = `<p class="no-messages">No ${type.replace('-', ' ').toLowerCase()} messages found.</p>`;
            return;
        }

        const ul = document.createElement('ul');
        ul.classList.add('message-list');

        messages.forEach(message => {
            const li = document.createElement('li');
            li.classList.add('message-item');

            if (type.includes('email')) { // 'email-spam'
                li.innerHTML = `
                    <div class="message-header">
                        <span class="message-sender">${message.sender}</span>
                        <span class="message-timestamp">${new Date(message.received_timestamp).toLocaleString()}</span>
                    </div>
                    <div class="message-subject">Subject: ${message.subject || '(No Subject)'}</div>
                    <div class="message-body-snippet">${message.body || '(No Content Preview)'}</div>
                    <div class="message-status status-${message.detection_status || 'undetermined'}">${message.detection_status || 'Undetermined'}</div>
                `;
            } else if (type.includes('sms')) { // 'sms-spam'
                li.innerHTML = `
                    <div class="message-header">
                        <span class="message-sender">From: ${message.sender_number}</span>
                        <span class="message-timestamp">${new Date(message.timestamp).toLocaleString()}</span>
                    </div>
                    <div class="message-content">${message.message_content}</div>
                    <div class="message-status status-${message.detection_status || 'undetermined'}">${message.detection_status || 'Undetermined'}</div>
                `;
            }
            ul.appendChild(li);
        });
        messageListContainer.appendChild(ul);
    }

    // --- Logout Functionality ---
    logoutButton.addEventListener('click', () => {
        localStorage.removeItem('access_token');
        alert('You have been logged out.');
        window.location.href = 'login.html';
    });

    // --- Initial setup on page load ---
    await fetchUserInfo(); 
    
    // Set default to Email Spam and fetch messages
    messageViewTypeSelect.value = 'email-spam'; // <-- Changed default selection
    fetchMessages('email-spam'); // <-- Changed initial fetch

    // Event listener for dropdown change
    messageViewTypeSelect.addEventListener('change', (event) => {
        fetchMessages(event.target.value);
    });
});