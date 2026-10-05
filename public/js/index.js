    // Function to log ONLY to the browser console
    function debugLog(message) {
      // Quiet by default. Turn on with localStorage.setItem('debug', '1') in the browser console.
      let on = false;
      try { on = localStorage.getItem('debug') === '1'; } catch (e) { /* storage blocked */ }
      if (!on) return;
      // In production, you might want to conditionally log based on a DEBUG flag,
      // or reduce the verbosity. For now, this ensures it doesn't break the page.
      console.log(`[index.html DEBUG] ${message}`);
    }
    
    // Check the stored session info and update the UI.
    // The real session is the httpOnly auth_token cookie, which scripts cannot read.
    // user_email and user_role are display hints only. The server enforces access.
    function checkToken() {
      const email = localStorage.getItem('user_email');
      const role = localStorage.getItem('user_role');
      
      const logoutButton = document.getElementById('logout-button');
      const loginLink = document.getElementById('login-link');
      const registerLink = document.getElementById('register-link');
      const adminPanelLink = document.getElementById('admin-panel-link');
      const usersLink = document.getElementById('users-link');

      // Default to non-authenticated UI state
      if(logoutButton) logoutButton.style.display = 'none';
      if(adminPanelLink) adminPanelLink.style.display = 'none';
      if(usersLink) usersLink.style.display = 'none';
      if(loginLink) loginLink.style.display = 'inline-block';
      if(registerLink) registerLink.style.display = 'inline-block';
      
      if (email) {
        debugLog('Found stored session info');
        if(logoutButton) logoutButton.style.display = 'inline-block';
        if(loginLink) loginLink.style.display = 'none';
        if(registerLink) registerLink.style.display = 'none';
        
        if (role && role.toLowerCase() === 'admin') {
          debugLog('Admin role stored, showing admin links');
          if(adminPanelLink) adminPanelLink.style.display = 'inline-block';
          if(usersLink) usersLink.style.display = 'inline-block';
        }
      } else {
        debugLog('No stored session info. Showing non-authenticated UI.');
      }
    }
    
    // Handle logout
    async function logout() {
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user_role');
      localStorage.removeItem('user_email');
      try {
        // The auth cookie is httpOnly, so the server has to clear it
        await fetch('/api/logout', { method: 'POST', credentials: 'include' });
      } catch (e) {
        debugLog(`Logout request failed: ${e.message}`);
      }
      debugLog('Logged out - stored session info cleared and cookie cleared by server.');
      window.location.reload();
    }
    
    // Run when page loads
    document.addEventListener('DOMContentLoaded', function() {
      debugLog('Page loaded, checking auth status');
      
      const logoutBtnInstance = document.getElementById('logout-button');
      if (logoutBtnInstance) {
        logoutBtnInstance.addEventListener('click', logout);
      } else {
        debugLog("Logout button not found on this page (this is normal for pages like login.html).");
      }
      
      // Check token on page load to set up initial UI
      checkToken();
    });
