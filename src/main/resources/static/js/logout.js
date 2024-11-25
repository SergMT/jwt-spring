

async function logout() {
    try {
        const response = await fetch(`${API_BASE_URL}/auth/logout`, {
            method: 'POST', // Logout uses POST as per convention
            headers: { 'Content-Type': 'application/json' },
            //credentials: 'include' // Ensure cookies are sent with the request
        });

        if (response.ok) {
            alert('Logged out successfully!');
            // Redirect to the login page
            window.location.href = '/';
        } else {
            console.error('Failed to log out:', response);
            alert('Logout failed. Please try again.');
        }
    } catch (error) {
        console.error('Error during logout:', error);
        alert('An error occurred while logging out.');
    }
}

