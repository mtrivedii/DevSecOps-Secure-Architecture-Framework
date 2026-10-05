    // Check authentication and render appropriate content
    document.addEventListener('DOMContentLoaded', function() {
      // Get cookie helper function
      const getCookie = (name) => {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
      };
      
      // Display hints only. The auth cookie is httpOnly and the server enforces access.
      const userEmail = localStorage.getItem('user_email');
      const userRole = localStorage.getItem('user_role');
      
      const container = document.getElementById('content-container');
      
      // If authenticated as admin, show admin page
      if (userEmail && userRole && userRole.toLowerCase() === 'admin') {
        container.innerHTML = `
          <div class="container">
            <h1>🔐 Admin Control Panel</h1>
            <p>Welcome to the administrator control panel. From here you can manage system settings and user permissions.</p>
            
            <div class="admin-dashboard">
              <div class="admin-card">
                <h2>🔍 System Status</h2>
                <p>All systems operational</p>
                <div class="status-indicator active"></div>
              </div>
              
              <div class="admin-card">
                <h2>👥 User Management</h2>
                <p>Current active users: <strong>1</strong></p>
                <a href="/users.html" class="button">Manage Users</a>
              </div>
              
              <div class="admin-card">
                <h2>📊 Security Logs</h2>
                <p>Recent sign-in and access events, with alerts</p>
                <a href="/security.html" class="button">View Security Events</a>
              </div>
            </div>
            
            <div class="button-container">
              <a class="button secondary" href="index.html">← Back to Home</a>
              <button id="logout-button" class="button warning">Logout</button>
            </div>
          </div>
        `;
        
        // Add logout functionality
        document.getElementById('logout-button').addEventListener('click', async function() {
          localStorage.removeItem('auth_token');
          localStorage.removeItem('user_role');
          localStorage.removeItem('user_email');
          try {
            await fetch('/api/logout', { method: 'POST', credentials: 'include' });
          } catch (e) {}
          window.location.href = '/';
        });
      } 
      // If not authenticated or not admin, show unauthorized page
      else {
        container.innerHTML = `
          <div class="container">
            <h1>🔒 Unauthorized Access</h1>
            
            <div class="card">
              <h2>Authentication Required</h2>
              <p>You must be logged in with appropriate permissions to access this page.</p>
              <div class="button-container">
                <a href="/login.html" class="button">Login</a>
                <a href="/" class="button secondary">Return to Home</a>
              </div>
            </div>
          </div>
        `;
      }
    });
