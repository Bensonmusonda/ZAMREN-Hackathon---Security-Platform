// scripts/sent_logic.js

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
        // No token found, redirect to login
        alert('You are not logged in. Please log in to access your sent messages.'); // Updated alert
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

            if (await handleUnauthorized(response)) return; // Redirect if unauthorized

            if (!response.ok) {
                throw new Error(`Failed to fetch user info: ${response.status}`);
            }

            const userData = await response.json();
            userDisplayName.textContent = `${userData.first_name} ${userData.last_name}`; // Display user's name
        } catch (error) {
            console.error('Error fetching user info:', error);
            userDisplayName.textContent = 'User Info Error';
        }
    }


    // --- Function to fetch messages (Emails or SMS) ---
    async function fetchMessages(type) {
        messageListContainer.innerHTML = '<p class="loading-message">Loading messages...</p>';
        // Update title based on selected type
        if (type === 'email-sent') {
            inboxTitle.textContent = 'Your Sent Emails';
        } else if (type === 'sms-sent') {
            inboxTitle.textContent = 'Your Sent SMS';
        }


        let url = '';
        if (type === 'email-sent') {
            url = `${MAIN_IDS_BASE_URL}/user/emails/sent`; // <-- CHANGED URL for sent emails
        } else if (type === 'sms-sent') {
            url = `${MAIN_IDS_BASE_URL}/user/sms/sent`; // <-- URL for sent SMS (already existed)
        }

        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}` // Include the JWT in the header
                }
            });

            if (await handleUnauthorized(response)) return; // Redirect if unauthorized

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
        messageListContainer.innerHTML = ''; // Clear loading message

        if (messages.length === 0) {
            messageListContainer.innerHTML = `<p class="no-messages">No ${type.replace('-', ' ').toLowerCase()} messages found.</p>`;
            return;
        }

        const ul = document.createElement('ul');
        ul.classList.add('message-list');

        messages.forEach(message => {
            const li = document.createElement('li');
            li.classList.add('message-item');

            // The display logic for emails and SMS remains the same as inbox,
            // as the structure of the data (sender, subject, body/content) is consistent.
            if (type.includes('email')) { // Use .includes('email') for both 'email-inbox' and 'email-sent'
                li.innerHTML = `
                    <div class="message-header">
                        <span class="message-sender">${message.recipients.join(', ')}</span> <span class="message-timestamp">${new Date(message.received_timestamp).toLocaleString()}</span>
                    </div>
                    <div class="message-subject">Subject: ${message.subject || '(No Subject)'}</div>
                    <div class="message-body-snippet">${message.body || '(No Content Preview)'}</div>
                    <div class="message-status status-${message.detection_status || 'undetermined'}">${message.detection_status || 'Undetermined'}</div>
                `;
            } else if (type.includes('sms')) { // Use .includes('sms') for both 'sms-inbox' and 'sms-sent'
                li.innerHTML = `
                    <div class="message-header">
                        <span class="message-sender">To: ${message.recipient_number}</span> <span class="message-timestamp">${new Date(message.timestamp).toLocaleString()}</span>
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
        localStorage.removeItem('access_token'); // Clear the stored token
        alert('You have been logged out.');
        window.location.href = 'login.html'; // Redirect to login page
    });

    // --- Initial setup on page load ---
    await fetchUserInfo(); 
    
    // Set default to Email Sent and fetch messages
    messageViewTypeSelect.value = 'email-sent'; // <-- Changed default selection
    fetchMessages('email-sent'); // <-- Changed initial fetch

    // Event listener for dropdown change
    messageViewTypeSelect.addEventListener('change', (event) => {
        fetchMessages(event.target.value);
    });
});