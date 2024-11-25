const API_BASE_URL = 'http://localhost:8080';

// Login
async function login(){
  
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
  
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        
        console.log('Login response:', data);
        sessionStorage.setItem("jwtToken", data.access_token)

        alert('Logged in successfully!');
        console.log(sessionStorage.jwtToken)

        //setTimeout(fetchIndexData(sessionStorage.jwtToken), 30000)

        fetchIndexData(sessionStorage.jwtToken)

    } catch (error) {

      console.error('Error during login:', error);
      alert('Login failed.');

    }
  }

  async function fetchIndexData(token) {
    const url = '/index'; // API endpoint
  
    try {
      const response = await fetch(url, {
        method: 'GET', // Use GET or appropriate method
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`, // Include the JWT token
        },
      });
  
      if (!response.ok) {
        // Handle HTTP errors
        throw new Error(`HTTP error! Status: ${response.status}`);
      }

      // Render the content in the same page
      const html = await response.text();
      document.body.innerHTML = html; // Load the new content
    
    } catch (error) {
      
      console.error('Error fetching /index:', error);
      alert('No tiene autorización. Redirigiendo a login...');
      window.location.href = '/'; // Redirect to login on error
    }
  }
  
