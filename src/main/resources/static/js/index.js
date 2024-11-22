// console.log("cargando index.html");

// const API_BASE_URL = 'http://localhost:8080';
// const token = sessionStorage.getItem('jwtToken');
// console.log("JWT Token:", token);

// fetch(`${API_BASE_URL}/index`, {
//   method: 'GET',
//   headers: {
//       'Content-Type': 'application/json',
//       'Authorization': `Bearer ${token}`, // Debug the token value here
//   },
// })
//   .then(response => {
//       console.log("Response status:", response.status);
//       if (response.ok) {
//           return response.text();
//       } else {
//           console.error("Unauthorized access. Redirecting...");
//           window.location.href = '/';
//       }
//   })
//   .then(html => {
//       console.log("Page content loaded successfully");
//       document.body.innerHTML = html;
//   })
//   .catch(error => console.error("Error fetching /index:", error));





// let jwtToken = '';

// Register
// document.getElementById('register-form').addEventListener('submit', async (e) => {
//   e.preventDefault();

//   const name = document.getElementById('name').value;
//   const email = document.getElementById('email').value;
//   const password = document.getElementById('password').value;

//   try {
//     const response = await fetch(`${API_BASE_URL}/auth/register`, {
//       method: 'POST',
//       headers: { 'Content-Type': 'application/json' },
//       body: JSON.stringify({ name, email, password })
//     });

//     const data = await response.json();
//     console.log('Register response:', data);
//     alert('User registered successfully!');
//   } catch (error) {
//     console.error('Error during registration:', error);
//     alert('Registration failed.');
//   }
// });

// Refresh Token
// document.getElementById('refresh-token').addEventListener('click', async () => {
//   if (!jwtToken) {
//     alert('Please log in first.');
//     return;
//   }

//   try {
//     const response = await fetch(`${API_BASE_URL}/auth/refresh-token`, {
//       method: 'POST',
//       headers: { 
//         'Content-Type': 'application/json',
//         'Authorization': `Bearer ${jwtToken}`
//       }
//     });

//     const data = await response.json();
//     jwtToken = data.token;
//     console.log('Refresh token response:', data);
//     alert('Token refreshed successfully!');
//   } catch (error) {
//     console.error('Error during token refresh:', error);
//     alert('Token refresh failed.');
//   }
// });

// Fetch Users
// document.getElementById('fetch-users').addEventListener('click', async () => {
//   if (!jwtToken) {
//     alert('Please log in first.');
//     return;
//   }

//   try {
//     const response = await fetch(`${API_BASE_URL}/users`, {
//       method: 'GET',
//       headers: { 'Authorization': `Bearer ${jwtToken}` }
//     });

//     const users = await response.json();
//     console.log('Users:', users);

//     const usersList = document.getElementById('users-list');
//     usersList.innerHTML = '';
//     users.forEach(user => {
//       const li = document.createElement('li');
//       li.textContent = `${user.name} (${user.email})`;
//       usersList.appendChild(li);
//     });
//   } catch (error) {
//     console.error('Error fetching users:', error);
//     alert('Failed to fetch users.');
//   }
// });
