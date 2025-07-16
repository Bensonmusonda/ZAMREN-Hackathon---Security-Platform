// js/signup_logic.js

document.addEventListener('DOMContentLoaded', () => {
    const firstNameInput = document.getElementById('first-name-box');
    const lastNameInput = document.getElementById('last-name-box');
    const emailInput = document.getElementById('email-box');
    const phoneInput = document.getElementById('phone-box');
    const passwordInput = document.getElementById('password-box'); // New
    const confirmPasswordInput = document.getElementById('confirm-password-box'); // New
    const registerButton = document.getElementById('submit'); // Your button's ID is 'submit'
    const headerText = document.getElementById('header-text'); // To display messages

    // --- IMPORTANT: Your Main IDS Backend URL ---
    // Ensure this matches where your detection_and_logging/main.py is running.
    const SERVER_IP = "192.168.56.1"
    const MAIN_IDS_BASE_URL = `http://${SERVER_IP}:8000`;
    // ---------------------------------------------

    registerButton.addEventListener('click', async (event) => {
        event.preventDefault(); // Prevent default form submission

        const firstName = firstNameInput.value.trim();
        const lastName = lastNameInput.value.trim();
        const email = emailInput.value.trim();
        const phone = phoneInput.value.trim();
        const password = passwordInput.value.trim();
        const confirmPassword = confirmPasswordInput.value.trim();

        if (!firstName || !lastName || !email || !password || !confirmPassword) {
            headerText.textContent = "Please fill in all required fields.";
            headerText.style.color = "red";
            return;
        }

        if (password !== confirmPassword) {
            headerText.textContent = "Passwords do not match.";
            headerText.style.color = "red";
            return;
        }
        
        // Simple email format validation (can be more robust on backend)
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            headerText.textContent = "Please enter a valid email address.";
            headerText.style.color = "red";
            return;
        }

        registerButton.textContent = "Registering...";
        registerButton.disabled = true;
        headerText.textContent = "Registering account...";
        headerText.style.color = "initial"; // Reset color

        const userData = {
            username: email, // Using email as username for login, or create a separate username field
            first_name: firstName,
            last_name: lastName,
            email: email,
            phone: phone,
            password: password // Send plain password, backend will hash it
        };

        try {
            const response = await fetch(`${MAIN_IDS_BASE_URL}/register`, { // New /register endpoint
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(userData)
            });

            if (!response.ok) {
                const errorData = await response.json();
                console.error('Registration error:', errorData);
                headerText.textContent = errorData.detail || 'Registration failed.';
                headerText.style.color = "red";
                return;
            }

            const data = await response.json();
            console.log('Registration successful:', data);
            headerText.textContent = "Registration successful! You can now login.";
            headerText.style.color = "green";

            // Optional: Clear form or redirect to login
            firstNameInput.value = '';
            lastNameInput.value = '';
            emailInput.value = '';
            phoneInput.value = '';
            passwordInput.value = '';
            confirmPasswordInput.value = '';
            
            // Redirect to login page after a short delay
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 2000);

        } catch (error) {
            console.error('Network or unexpected registration error:', error);
            headerText.textContent = 'A network error occurred during registration. Please try again.';
            headerText.style.color = "red";
        } finally {
            registerButton.textContent = "Register";
            registerButton.disabled = false;
        }
    });
});