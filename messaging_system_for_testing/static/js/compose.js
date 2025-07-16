document.addEventListener('DOMContentLoaded', () => {
    const messageTypeSelect = document.getElementById('message-type');
    const recipientInput = document.getElementById('recipient-input');
    const subjectGroup = document.getElementById('subject-group');
    const subjectInput = document.getElementById('subject-input');
    const messageBody = document.getElementById('message-body');
    const sendButton = document.getElementById('send-button');

    // Function to toggle subject input visibility
    const toggleSubjectInput = () => {
        if (messageTypeSelect.value === 'email') {
            subjectGroup.style.display = 'flex'; // Or 'block', depending on your CSS layout for input-group
            subjectInput.required = true;
        } else {
            subjectGroup.style.display = 'none';
            subjectInput.required = false;
            subjectInput.value = ''; // Clear subject when switching to SMS
        }
    };

    // Initial call to set correct state on page load
    toggleSubjectInput();

    // Event listener for message type change
    messageTypeSelect.addEventListener('change', () => {
        toggleSubjectInput();
        // Adjust placeholder text based on message type
        if (messageTypeSelect.value === 'email') {
            recipientInput.placeholder = 'Recipient Email';
        } else {
            recipientInput.placeholder = 'Recipient Phone Number';
        }
    });

    // Event listener for the Send button
    sendButton.addEventListener('click', async (event) => {
        event.preventDefault(); // Prevent default form submission

        const messageType = messageTypeSelect.value;
        const recipient = recipientInput.value.trim();
        const body = messageBody.value.trim();
        const sender = "compose_user@bennieslab.com"; // You might want to make this dynamic later

        // Basic validation
        if (!recipient || !body) {
            alert('Please fill in recipient and message body.');
            return;
        }

        let payload = {
            message_type: messageType,
            recipient: recipient,
            body: body,
            sender: sender // Included for both email and SMS, but primarily for email
        };

        if (messageType === 'email') {
            const subject = subjectInput.value.trim();
            if (!subject) {
                alert('Please fill in the subject for email.');
                return;
            }
            payload.subject = subject;
        }

        try {
            // Send data to your FastAPI backend
            const response = await fetch('/api/send-message', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
            });

            if (response.ok) {
                const result = await response.json();
                alert(`Message sent successfully! Status: ${result.status}`);
                // Clear the form on successful send
                recipientInput.value = '';
                subjectInput.value = '';
                messageBody.value = '';
                messageTypeSelect.value = 'email'; // Reset to email
                toggleSubjectInput(); // Re-toggle subject input visibility
            } else {
                const errorData = await response.json();
                alert(`Failed to send message: ${errorData.detail || response.statusText}`);
            }
        } catch (error) {
            console.error('Error sending message:', error);
            alert('An error occurred while sending the message. Please check the console for details.');
        }
    });
});