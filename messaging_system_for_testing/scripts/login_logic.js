// scripts/login_logic.js

document.addEventListener('DOMContentLoaded', () => {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const loginButton = document.getElementById('submit'); // Your button's ID is 'submit'
    // CHANGE THIS LINE:
    const welcomeText = document.getElementById('message-text'); // Corrected to match HTML ID

    // --- IMPORTANT: Your Main IDS Backend URL ---
    // Ensure this matches where your detection_and_logging/main.py is running.
    const SERVER_IP = "192.168.56.1"
    const MAIN_IDS_BASE_URL = `http://${SERVER_IP}:8000`;
    // ---------------------------------------------

    loginButton.addEventListener('click', async () => {
        const username = usernameInput.value.trim(); // Can be email or username
        const password = passwordInput.value.trim();

        if (!username || !password) {
            welcomeText.textContent = "Please enter both username/email and password.";
            welcomeText.style.color = "red";
            return;
        }

        loginButton.textContent = "Logging in...";
        loginButton.disabled = true;
        welcomeText.textContent = "Logging in...";
        welcomeText.style.color = "initial"; // Reset color

        // Prepare data for x-www-form-urlencoded
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);

        try {
            const response = await fetch(`${MAIN_IDS_BASE_URL}/token`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData.toString()
            });

            if (!response.ok) {
                const errorData = await response.json();
                console.error('Login error:', errorData);
                welcomeText.textContent = errorData.detail || 'Login failed. Please check your credentials.';
                welcomeText.style.color = "red";
                return;
            }

            const data = await response.json();
            localStorage.setItem('access_token', data.access_token); // Store the JWT
            console.log('Login successful, token stored:', data.access_token);
            welcomeText.textContent = "Login successful! Redirecting...";
            welcomeText.style.color = "green";

            // Redirect to the inbox page after successful login
            window.location.href = 'inbox.html';

        } catch (error) {
            console.error('Network or unexpected login error:', error);
            welcomeText.textContent = 'A network error occurred. Please try again.';
            welcomeText.style.color = "red";
        } finally {
            loginButton.textContent = "login";
            loginButton.disabled = false;
        }
    });
});