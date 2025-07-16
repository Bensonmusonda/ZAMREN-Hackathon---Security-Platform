// scripts/compose_logic.js

// Function to update visibility of the subject field based on message type
function updateSubjectFieldVisibility() {
    const messageType = document.getElementById('message-type').value;
    const subjectGroup = document.getElementById('subject-group');
    if (messageType === 'email') {
        subjectGroup.style.display = 'block'; // Show for email
    } else {
        subjectGroup.style.display = 'none'; // Hide for SMS
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    // Get references to HTML elements
    const messageTypeSelect = document.getElementById('message-type');
    const recipientInput = document.getElementById('email-or-number');
    const subjectInput = document.getElementById('subject');
    const messageTextarea = document.querySelector('.message-textarea');
    const sendButton = document.querySelector('.send-button');
    const userDisplayName = document.getElementById('user-display-name');
    const logoutButton = document.getElementById('logout-button');

    // New elements for file attachment
    const attachmentInput = document.getElementById('attachment-input');
    const attachFileButton = document.getElementById('attach-file-button');
    const attachImageButton = document.getElementById('attach-image-button'); 
    const attachedFileDisplay = document.getElementById('attached-file-display'); // The container div
    const selectedFileNameSpan = document.getElementById('selected-file-name'); // The span for the file name
    const removeFileButton = document.getElementById('remove-file-button'); // The 'X' button

    // --- IMPORTANT: Subsystem Manager URLs ---
    const SERVER_IP = "192.168.56.1"
    const EMAIL_MANAGER_URL = `http://${SERVER_IP}:5000/ingest-email`;
    const SMS_MANAGER_URL = `http://${SERVER_IP}:8001/detect_sms`;
    const MAIN_IDS_BASE_URL = `http://${SERVER_IP}:8000`;
    // -----------------------------------------

    let currentUserEmail = null;
    let currentUserPhone = null;
    let currentUserId = null;
    let selectedFile = null; // Variable to store the selected file object

    console.log("DOM Content Loaded. Initializing script.");
    console.log("Elements found:");
    console.log("  attachmentInput:", attachmentInput);
    console.log("  attachFileButton:", attachFileButton);
    console.log("  attachImageButton:", attachImageButton);
    console.log("  attachedFileDisplay:", attachedFileDisplay);
    console.log("  selectedFileNameSpan:", selectedFileNameSpan);
    console.log("  removeFileButton:", removeFileButton);


    // --- Authentication Check & User Info Fetch ---
    const token = localStorage.getItem('access_token');
    if (!token) {
        console.log('No token found. Redirecting to login.');
        alert('You are not logged in. Please log in to compose messages.');
        window.location.href = 'login.html';
        return;
    }

    async function handleUnauthorized(response) {
        if (response.status === 401) {
            console.warn('Authentication failed (401). Clearing token and redirecting.');
            localStorage.removeItem('access_token'); // Clear invalid token
            alert('Your session has expired or is invalid. Please log in again.');
            window.location.href = 'login.html';
            return true;
        }
        return false;
    }

    try {
        console.log(`Fetching current user info from: ${MAIN_IDS_BASE_URL}/current_user`);
        const response = await fetch(`${MAIN_IDS_BASE_URL}/current_user`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (await handleUnauthorized(response)) return;

        if (!response.ok) {
            throw new Error(`Failed to fetch current user info: ${response.status}`);
        }

        const userData = await response.json();
        currentUserEmail = userData.email;
        currentUserPhone = userData.phone;
        currentUserId = userData.id;
        userDisplayName.textContent = `${userData.first_name} ${userData.last_name}`;

        console.log('Logged-in user email:', currentUserEmail);
        console.log('Logged-in user phone:', currentUserPhone);
        console.log('Logged-in user ID:', currentUserId);

    } catch (error) {
        console.error('Error fetching user info for compose page:', error);
        alert('Failed to load sender information. Please try logging in again.');
        localStorage.removeItem('access_token');
        window.location.href = 'login.html';
        return;
    }
    // ---------------------------------------------------

    logoutButton.addEventListener('click', () => {
        console.log('Logout button clicked.');
        localStorage.removeItem('access_token');
        alert('You have been logged out.');
        window.location.href = 'login.html';
    });

    updateSubjectFieldVisibility();
    messageTypeSelect.addEventListener('change', updateSubjectFieldVisibility);

    // --- Attachment Handling Logic ---
    function updateAttachedFileDisplay() {
        console.log('updateAttachedFileDisplay called. selectedFile:', selectedFile);
        if (selectedFile) {
            selectedFileNameSpan.textContent = selectedFile.name;
            // Add the class to show it and apply its styles
            attachedFileDisplay.classList.add('active-file-display'); 
            console.log(`Displaying file: ${selectedFile.name}. Added 'active-file-display' class.`);
        } else {
            selectedFileNameSpan.textContent = '';
            // Remove the class to hide it
            attachedFileDisplay.classList.remove('active-file-display'); 
            console.log('No file selected. Removed "active-file-display" class.');
        }
    }

    attachFileButton.addEventListener('click', () => {
        console.log('Attach File button clicked. Triggering attachmentInput click.');
        attachmentInput.click(); // Trigger the hidden file input click
    });

    attachImageButton.addEventListener('click', () => {
        console.log('Attach Image button clicked. Triggering attachmentInput click.');
        attachmentInput.click(); // Trigger the hidden file input click
    });

    attachmentInput.addEventListener('change', (event) => {
        console.log('attachmentInput change event fired.');
        selectedFile = event.target.files[0]; // Get the first selected file
        if (selectedFile) {
            console.log('File selected:', selectedFile.name, selectedFile.type, selectedFile.size);
        } else {
            console.log('No file selected in change event.');
        }
        updateAttachedFileDisplay(); // Update display based on selection
    });

    removeFileButton.addEventListener('click', () => {
        console.log('Remove File button clicked.');
        selectedFile = null; // Clear the stored file object
        attachmentInput.value = ''; // Clear the file input's value (important for re-selecting same file)
        updateAttachedFileDisplay(); // Hide the display
    });
    // --- End Attachment Handling Logic ---


    sendButton.addEventListener('click', async () => {
        const messageType = messageTypeSelect.value;
        const recipient = recipientInput.value.trim();
        const subject = subjectInput.value.trim();
        const messageContent = messageTextarea.value.trim();

        // Basic validation
        if (!recipient || !messageContent) {
            alert('Please fill in both the recipient and message content.');
            return;
        }

        if (messageType === 'email' && !subject) {
            alert('Please enter a subject for the email.');
            return;
        }

        let requestBody;
        let apiUrl = '';
        let successMessage = '';
        let errorMessage = '';
        let headers = {};

        const composedTimestamp = new Date().toISOString(); 

        if (messageType === 'email') {
            if (!currentUserEmail) {
                alert("Your account does not have an email associated to send emails.");
                return;
            }
            apiUrl = EMAIL_MANAGER_URL;

            const emailDataForManager = {
                sender: currentUserEmail,
                recipients: [recipient],
                subject: subject,
                body: messageContent
            };

            const formData = new FormData();
            formData.append('email_json_data', JSON.stringify(emailDataForManager));

            if (selectedFile) {
                formData.append('attachment', selectedFile);
                console.log(`Attaching file: ${selectedFile.name}, type: ${selectedFile.type}, size: ${selectedFile.size} bytes`);
            } else {
                console.log("No file selected for email attachment.");
            }

            requestBody = formData;
            
            console.log("Frontend FormData being sent to Email Manager:");
            for (let pair of formData.entries()) {
                console.log(pair[0]+ ': ' + pair[1]);
            }

            successMessage = 'Email sent for detection and attachment processing!';
            errorMessage = 'Failed to send email to manager.';

        } else if (messageType === 'sms') {
            if (!currentUserPhone) {
                alert("Your account does not have a phone number associated to send SMS.");
                return;
            }
            apiUrl = SMS_MANAGER_URL;
            const payload = {
                sms_id: `composed-${crypto.randomUUID().substring(0, 8)}-${Date.now()}`,
                timestamp: composedTimestamp,
                sender_number: currentUserPhone,
                recipient_number: recipient,
                message_content: messageContent,
                details: {
                    composed_by_user_id: currentUserId,
                    composed_via_app: true
                }
            };
            requestBody = JSON.stringify(payload);
            headers = { 'Content-Type': 'application/json' };
            successMessage = 'SMS sent for detection!';
            errorMessage = 'Failed to send SMS to manager.';
        }

        sendButton.textContent = 'Sending...';
        sendButton.disabled = true;

        try {
            const fetchOptions = {
                method: 'POST',
                body: requestBody
            };

            if (Object.keys(headers).length > 0) {
                fetchOptions.headers = headers;
            }

            console.log(`Sending fetch request to: ${apiUrl}`);
            const response = await fetch(apiUrl, fetchOptions);
            console.log(`Fetch response status: ${response.status}`);

            if (!response.ok) {
                const errorData = await response.json();
                console.error(`HTTP error! Status: ${response.status}`, errorData);
                alert(`${errorMessage}\nServer Response: ${JSON.stringify(errorData.detail || errorData)}`);
                return;
            }

            const responseData = await response.json();
            console.log('Success:', responseData);
            alert(successMessage);

            // Clear form fields after successful send
            recipientInput.value = '';
            subjectInput.value = '';
            messageTextarea.value = '';
            
            // Clear attachment related fields
            selectedFile = null;
            attachmentInput.value = ''; // Clear selected file from input
            updateAttachedFileDisplay(); // Hide the display

        } catch (error) {
            console.error('Network or other error during fetch:', error);
            alert(`${errorMessage}\nError: ${error.message}`);
        } finally {
            sendButton.textContent = 'Send';
            sendButton.disabled = false;
        }
    });
});