document.addEventListener("DOMContentLoaded", () => {
    // Attach a click event listener to the entire document
    document.body.addEventListener("click", () => {
        // Send a lightweight request to validate the token
        fetch("/auth/validate-token", {
            method: "GET",
            credentials: "include" // Ensures cookies like the JWT are sent
        })
        .then(response => {
            if (response.status === 401) {
                // Token is expired or invalid, redirect to login with a message
                window.location.href = "/?message=sessionExpired";
            }
        })
        .catch(error => {
            console.error("Error validating token:", error);
            // Optional: Handle errors, e.g., notify the user
        });
    });
});
