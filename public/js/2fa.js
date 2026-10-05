    document.addEventListener('DOMContentLoaded', function() {
      // Get parameters from URL
      const urlParams = new URLSearchParams(window.location.search);
      const userId = urlParams.get('userId');
      const email = urlParams.get('email');
      const isRequired = urlParams.get('setup') === 'required';
      
      // Show required notice if setup is mandatory
      if (isRequired) {
        document.getElementById('required-notice').style.display = 'block';
      }
      
      // If no user info, try to get from localStorage
      const finalUserId = userId || localStorage.getItem('pendingSetupUserId');
      const finalEmail = email || localStorage.getItem('pendingSetupEmail');
      
      // If still no user info, redirect to registration
      if (!finalUserId || !finalEmail) {
        window.location.href = '/register.html';
        return;
      }
      
      // Store for potential page refreshes
      localStorage.setItem('pendingSetupUserId', finalUserId);
      localStorage.setItem('pendingSetupEmail', finalEmail);
      
      const qrcodeImage = document.getElementById('qrcode');
      const secretKey = document.getElementById('secret-key');
      const verificationCode = document.getElementById('verification-code');
      const verifyButton = document.getElementById('verify-button');
      const setupMessage = document.getElementById('setup-message');
      const setupContainer = document.getElementById('setup-container');
      const successContainer = document.getElementById('success-container');
      const recoveryCodesList = document.getElementById('recovery-codes-list');
      
      // Function to show a message
      function showMessage(message, type) {
        setupMessage.textContent = message;
        setupMessage.className = `message ${type}`;
        setupMessage.style.display = 'block';
      }
      
      // Step 1: Set up 2FA (get QR code)
      async function setup2FA() {
        try {
          const response = await fetch('/api/2fa/setup', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId: finalUserId, email: finalEmail })
          });
          
          if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to set up 2FA');
          }
          
          const data = await response.json();
          
          // Display QR code and secret key
          qrcodeImage.src = data.qrCodeUrl;
          qrcodeImage.style.display = 'block';
          secretKey.textContent = data.secret;
          
          // Store secret for verification
          window.tempSecret = data.secret;
        } catch (error) {
          showMessage(error.message || 'An error occurred during 2FA setup', 'error');
        }
      }
      
      // Step 2: Verify and activate 2FA
      async function verify2FA() {
        const token = verificationCode.value.trim();
        
        if (!token || token.length !== 6 || !/^\d+$/.test(token)) {
          showMessage('Please enter a valid 6-digit verification code', 'error');
          return;
        }
        
        try {
          verifyButton.disabled = true;
          verifyButton.textContent = 'Verifying...';
          
          const response = await fetch('/api/2fa/verify', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId: finalUserId, token })
          });
          
          if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to verify 2FA token');
          }
          
          const data = await response.json();
          
          // Clear temporary storage
          localStorage.removeItem('pendingSetupUserId');
          localStorage.removeItem('pendingSetupEmail');
          
          // Display recovery codes
          if (data.recoveryCodes && data.recoveryCodes.length > 0) {
            recoveryCodesList.innerHTML = '';
            data.recoveryCodes.forEach(code => {
              const codeElement = document.createElement('code');
              codeElement.textContent = code;
              recoveryCodesList.appendChild(codeElement);
            });
          }
          
          // Show success screen
          setupContainer.style.display = 'none';
          successContainer.style.display = 'block';
        } catch (error) {
          showMessage(error.message || 'Failed to verify the code', 'error');
          verifyButton.disabled = false;
          verifyButton.textContent = 'Verify and Activate';
        }
      }
      
      // Initialize setup
      setup2FA();
      
      // Add event listener for verify button
      verifyButton.addEventListener('click', verify2FA);
      
      // Allow pressing Enter in the code input
      verificationCode.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
          verify2FA();
        }
      });
    });
