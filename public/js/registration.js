    document.addEventListener('DOMContentLoaded', function() {
      const form = document.getElementById('registrationForm');
      const passwordInput = document.getElementById('password');
      const confirmPasswordInput = document.getElementById('confirmPassword');
      const passwordMatchHint = document.getElementById('passwordMatch');
      const messageDiv = document.getElementById('registrationMessage');
      
      // Generate a CSRF token
      const csrfToken = generateCSRFToken();
      document.getElementById('csrfToken').value = csrfToken;
      
      // Check password match
      confirmPasswordInput.addEventListener('input', function() {
        if (passwordInput.value !== confirmPasswordInput.value) {
          passwordMatchHint.textContent = "Passwords do not match";
          passwordMatchHint.className = "hint error";
        } else {
          passwordMatchHint.textContent = "Passwords match";
          passwordMatchHint.className = "hint success";
        }
      });
      
      // Handle form submission
      form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Validate passwords match
        if (passwordInput.value !== confirmPasswordInput.value) {
          showMessage('Passwords do not match!', 'error');
          return;
        }
        
        // Collect form data
        const formData = {
          email: document.getElementById('email').value,
          password: document.getElementById('password').value,
          csrfToken: csrfToken
        };
        
        try {
          // Send registration request
          const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify(formData)
          });
          
          const data = await response.json();
          
          if (response.ok) {
            if (data.redirectTo) {
              // Redirect to 2FA setup if required
              localStorage.setItem('pendingSetupUserId', data.userId);
              localStorage.setItem('pendingSetupEmail', data.email);
              showMessage('Account created! Setting up security...', 'success');
              setTimeout(() => {
                window.location.href = data.redirectTo;
              }, 1000);
            } else {
              // Regular success case (without 2FA requirement)
              showMessage('Registration successful! Redirecting to login page...', 'success');
              // Clear the form
              form.reset();
              // Redirect after delay
              setTimeout(() => {
                window.location.href = '/login.html';
              }, 2000);
            }
          } else {
            // Show error message
            showMessage(`Registration failed: ${data.error}`, 'error');
          }
        } catch (error) {
          console.error('Error during registration:', error);
          showMessage('An error occurred during registration. Please try again.', 'error');
        }
      });
      
      // Helper functions
      function generateCSRFToken() {
        // Simple CSRF token generator - in real app, use a secure method
        return Math.random().toString(36).substring(2, 15) + 
               Math.random().toString(36).substring(2, 15);
      }
      
      function showMessage(message, type) {
        messageDiv.textContent = message;
        messageDiv.className = `message ${type}`;
        messageDiv.style.display = 'block';
      }
    });
