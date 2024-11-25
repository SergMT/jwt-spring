const API_BASE_URL = 'http://localhost:8080';

async function login() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });

        if (response.ok) {
            // Login successful
            alert('Logged in successfully! Redirecting to the index page...');
            console.log("Login response:", response);

            // Redirect to /index (the JWT cookie will automatically be sent by the browser)
            window.location.href = '/index';
        } else {
            // Login failed
            const error = await response.json();
            console.error('Login failed:', error);
            alert('Login failed: ' + (error.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error during login:', error);
        alert('Error. Usuario o contraseña incorrectos.');
    }
}

