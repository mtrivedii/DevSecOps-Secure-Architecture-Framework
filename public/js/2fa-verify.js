    function debugLog(message) {
      // Quiet by default. Turn on with localStorage.setItem('debug', '1') in the browser console.
      let on = false;
      try { on = localStorage.getItem('debug') === '1'; } catch (e) { /* storage blocked */ }
      if (!on) return;
      console.log(message);
      const debugOutput = document.getElementById('debug-output');
      
      if (debugOutput) {
        const timestamp = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.textContent = `[${timestamp}] ${message}`;
        debugOutput.appendChild(entry);
      }
    }
    
    document.addEventListener('DOMContentLoaded', function() {
      debugLog('2FA verification page loaded');
      
      // Get user info from URL parameters or local storage
      const urlParams = new URLSearchParams(window.location.search);
      const userId = urlParams.get('userId') || localStorage.getItem('pendingAuthUserId');
      const email = urlParams.get('email') || localStorage.getItem('pendingAuthEmail');
      
      debugLog(`User info: ID=${userId}, Email=${email}`);
      
      if (!userId || !email) {
        debugLog('No user info found, redirecting to login');
        window.location.href = '/login.html';
        return;
      }
      
      // Store for potential page refreshes
      localStorage.setItem('pendingAuthUserId', userId);
      localStorage.setItem('pendingAuthEmail', email);
      
      const verificationCode = document.getElementById('verification-code');
      const verifyButton = document.getElementById('verify-button');
      const useRecoveryLink = document.getElementById('use-recovery-link');
      const recoveryContainer = document.getElementById('recovery-container');
      const recoveryCode = document.getElementById('recovery-code');
      const recoveryButton = document.getElementById('recovery-button');
      const authMessage = document.getElementById('auth-message');
      
      // Function to show a message
      function showMessage(message, type) {
        authMessage.textContent = message;
        authMessage.className = `message ${type}`;
        authMessage.style.display = 'block';
        debugLog(`Message shown: ${message} (${type})`);
      }
      
      // Hide message
      function hideMessage() {
        authMessage.style.display = 'none';
      }
      
      // Handle TOTP verification
      async function verifyTOTP() {
        const token = verificationCode.value.trim();
        debugLog(`Attempting to verify code: ${token}`);
        
        if (!token || token.length !== 6 || !/^\d+$/.test(token)) {
          showMessage('Please enter a valid 6-digit verification code', 'error');
          return;
        }
        
        try {
          hideMessage();
          verifyButton.disabled = true;
          verifyButton.textContent = 'Verifying...';
          
          debugLog('Sending verification request to /api/2fa/validate');
          const response = await fetch('/api/2fa/validate', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId, token })
          });
          
          debugLog(`Server response status: ${response.status}`);
          
          // Parse response as text first to debug the raw response
          const responseText = await response.text();
          debugLog(`Raw response: ${responseText}`);
          
          // Then parse as JSON if possible
          let data;
          try {
            data = JSON.parse(responseText);
            debugLog(`Parsed response: ${JSON.stringify(data)}`);
          } catch (e) {
            debugLog(`Failed to parse response as JSON: ${e.message}`);
            throw new Error('Invalid server response format');
          }
          
          if (!response.ok) {
            throw new Error(data.error || 'Failed to verify code');
          }
          
          // The session is the httpOnly auth_token cookie set by the server.
          // Keep only display info (email and role) for the UI. The server enforces access.
          localStorage.removeItem('auth_token');
          if (data.user) {
            localStorage.setItem('user_email', data.user.email);
            localStorage.setItem('user_role', data.user.role || 'user');
            debugLog(`User info stored: ${data.user.email}`);
          }
          
          // Clear temporary 2FA auth data
          localStorage.removeItem('pendingAuthUserId');
          localStorage.removeItem('pendingAuthEmail');
          
          // Show success message
          showMessage('Verification successful! Redirecting...', 'success');
          
          // Redirect after delay
          setTimeout(() => {
            window.location.href = '/';
          }, 2000);
          
        } catch (error) {
          debugLog(`Error during verification: ${error.message}`);
          showMessage(error.message || 'Failed to verify the code', 'error');
          verifyButton.disabled = false;
          verifyButton.textContent = 'Verify';
        }
      }
      
      // Handle recovery code validation
      async function verifyRecoveryCode() {
        const token = recoveryCode.value.trim();
        debugLog(`Attempting to verify recovery code: ${token}`);
        
        if (!token || !/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(token)) {
          showMessage('Please enter a valid recovery code (XXXX-XXXX-XXXX)', 'error');
          return;
        }
        
        try {
          hideMessage();
          recoveryButton.disabled = true;
          recoveryButton.textContent = 'Verifying...';
          
          debugLog('Sending recovery code to /api/2fa/validate');
          const response = await fetch('/api/2fa/validate', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId, token })
          });
          
          debugLog(`Server response status: ${response.status}`);
          
          // Parse response as text first to debug the raw response
          const responseText = await response.text();
          debugLog(`Raw response: ${responseText}`);
          
          // Then parse as JSON if possible
          let data;
          try {
            data = JSON.parse(responseText);
            debugLog(`Parsed response: ${JSON.stringify(data)}`);
          } catch (e) {
            debugLog(`Failed to parse response as JSON: ${e.message}`);
            throw new Error('Invalid server response format');
          }
          
          if (!response.ok) {
            throw new Error(data.error || 'Failed to verify recovery code');
          }
          
          // The session is the httpOnly auth_token cookie set by the server.
          // Keep only display info (email and role) for the UI. The server enforces access.
          localStorage.removeItem('auth_token');
          if (data.user) {
            localStorage.setItem('user_email', data.user.email);
            localStorage.setItem('user_role', data.user.role || 'user');
            debugLog(`User info stored: ${data.user.email}`);
          }
          
          // Clear temporary 2FA auth data
          localStorage.removeItem('pendingAuthUserId');
          localStorage.removeItem('pendingAuthEmail');
          
          // Show success message
          showMessage('Verification successful! Redirecting...', 'success');
          
          // Redirect after delay
          setTimeout(() => {
            window.location.href = '/';
          }, 2000);
          
        } catch (error) {
          debugLog(`Error during recovery code verification: ${error.message}`);
          showMessage(error.message || 'Failed to verify the recovery code', 'error');
          recoveryButton.disabled = false;
          recoveryButton.textContent = 'Use Recovery Code';
        }
      }
      
      // Add event listeners
      verifyButton.addEventListener('click', verifyTOTP);
      
      verificationCode.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
          verifyTOTP();
        }
      });
      
      useRecoveryLink.addEventListener('click', function(e) {
        e.preventDefault();
        recoveryContainer.style.display = recoveryContainer.style.display === 'none' ? 'block' : 'none';
      });
      
      recoveryButton.addEventListener('click', verifyRecoveryCode);
      
      recoveryCode.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
          verifyRecoveryCode();
        }
      });
    });
