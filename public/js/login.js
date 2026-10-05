        function debugLog(message) {
      // Quiet by default. Turn on with localStorage.setItem('debug', '1') in the browser console.
      let on = false;
      try { on = localStorage.getItem('debug') === '1'; } catch (e) { /* storage blocked */ }
      if (!on) return;
      console.log(message);
      const debugOutput = document.getElementById('debugOutput');
      if (debugOutput) {
        const timestamp = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.textContent = `[${timestamp}] ${message}`;
        debugOutput.appendChild(entry);
      }
    }

    document.addEventListener('DOMContentLoaded', function() {
      debugLog('Login page loaded');

      const form = document.getElementById('loginForm');
      const messageDiv = document.getElementById('loginMessage');
      
      // Generate a CSRF token
      const csrfToken = generateCSRFToken();
      document.getElementById('csrfToken').value = csrfToken;
      debugLog('CSRF token generated');
      
      // Handle form submission
      form.addEventListener('submit', async function(e) {
        e.preventDefault();
        debugLog('Login form submitted');
        // Collect form data
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        
        const formData = {
          email: email,
          password: password,
          csrfToken: csrfToken
        };
        
        debugLog(`Attempting login for: ${email}`);
        showMessage('Logging in...', 'info');
        
        try {
          // Send login request
          debugLog('Sending login request to /api/login');
          const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify(formData)
          });
          
          debugLog(`Login response status: ${response.status}`);
          
          const responseText = await response.text();
          debugLog(`Raw response: ${responseText}`);
          
          let data;
          try {
            data = JSON.parse(responseText);
            debugLog(`Parsed response: ${JSON.stringify(data)}`);
          } catch (e) {
            debugLog(`Failed to parse response as JSON: ${e.message}`);
            showMessage('Invalid server response', 'error');
            return;
          }
          
          if (response.ok) {
            // Check if 2FA is required
            if (data.requireTwoFactor) {
              debugLog('2FA required');
              // Save user ID and email for the 2FA page
              localStorage.setItem('pendingAuthUserId', data.userId);
              localStorage.setItem('pendingAuthEmail', data.email);
              
              // Show transition message
              showMessage('Verification required! Redirecting...', 'info');
              
              // Redirect to 2FA verification page
              setTimeout(() => {
                const redirectTo = data.redirectTo || '/2fa-verify.html';
                window.location.href = redirectTo;
              }, 1000);
              return;
            }
            
            // The session lives in the httpOnly auth_token cookie set by the server.
            // Remove any token left in localStorage by older versions of this page.
            localStorage.removeItem('auth_token');
            
            // Store user info if available
            if (data.user) {
              localStorage.setItem('user_email', data.user.email);
              localStorage.setItem('user_role', data.user.role || 'user');
              debugLog(`User info stored: ${data.user.email}, role: ${data.user.role || 'user'}`);
            }
            
            // Show success message and redirect
            showMessage('Login successful! Redirecting...', 'success');
            
            // Redirect after delay
            setTimeout(() => {
              window.location.href = '/';
            }, 1000);
          } else {
            // Show error message
            const errorMsg = data.error || 'Invalid credentials';
            debugLog('Login failed: ' + errorMsg);
            showMessage(`Login failed: ${errorMsg}`, 'error');
          }
        } catch (error) {
          debugLog('Error during login: ' + error.message);
          showMessage('Connection error. Please try again.', 'error');
        }
      });
      
      // Helper functions
      function generateCSRFToken() {
        return Math.random().toString(36).substring(2, 15) + 
               Math.random().toString(36).substring(2, 15);
      }
      
      function showMessage(message, type) {
        messageDiv.textContent = message;
        messageDiv.className = `message ${type}`;
        messageDiv.style.display = 'block';
      }
    });
